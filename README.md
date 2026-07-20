# masque-tunnel

A high-performance MASQUE tunnel — CONNECT-UDP ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)) and CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) — both client and server in a single binary.

Tunnels UDP traffic (or, with CONNECT-IP, arbitrary IP traffic) through HTTP/3 (QUIC) DATAGRAM frames on port 443, making it indistinguishable from normal HTTPS traffic. Designed for use as a VPN obfuscation layer (e.g., tunneling WireGuard) or as a standalone IP-layer VPN.

## Background

`masque-tunnel` was extracted from [Xlarva](https://xlarva.app/), a multi-platform WireGuard client for iOS, macOS, and tvOS. While building Xlarva's obfuscation features, we needed an RFC-compliant way to wrap WireGuard's UDP traffic inside an encrypted, indistinguishable-from-HTTPS transport. The popular [`wstunnel`](https://github.com/erebe/wstunnel) project covers TCP-style encapsulation over WebSockets, but it doesn't preserve UDP semantics — turning a UDP-only protocol like WireGuard into a TCP-over-TCP nightmare on lossy networks.

MASQUE CONNECT-UDP ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)) solves exactly this: it carries UDP datagrams natively over HTTP/3 / QUIC, the same protocol stack used by Apple iCloud Private Relay and Cloudflare WARP. We built this server (and a thin reference client) so any Xlarva user — or anyone else who wants a self-hosted, RFC-standard alternative to closed proxy services — can stand up their own relay in minutes.


## Features

- **[RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298) compliant** — CONNECT-UDP over HTTP/3 with QUIC DATAGRAM frames
- **[RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484) CONNECT-IP** — full IP-layer VPN over the same HTTP/3 transport (capsule protocol, dual-stack IPv4/IPv6 address assignment, TUN devices)
- **Client + Server** — single binary with `client` / `client-ip` / `server` subcommands
- **Full-tunnel mode** — `--redirect-gateway` takes over the default route (pins the proxy, installs a split default) and `--dns` overrides the system resolver; both revert on exit
- **Happy Eyeballs** — races IPv4/IPv6 handshakes (RFC 8305) so a dead address family never wedges the client
- **Path MTU discovery** — oversized packets get an ICMP Packet Too Big reply (RFC 9484 §7.1) instead of a silent drop
- **High throughput** — BBR2 congestion control, pre-allocated forwarding buffers
- **Obfuscation** — traffic appears as standard HTTPS/QUIC on port 443
- **Authentication** — optional Bearer token for client verification
- **SNI override** — supports domain fronting via custom TLS SNI
- **Resilient client** — keepalive keeps idle tunnels up; automatic reconnect with exponential backoff if the connection drops
- **Production QUIC stack** — built on Cloudflare [quiche](https://github.com/cloudflare/quiche) + [tokio-quiche](https://crates.io/crates/tokio-quiche) (BoringSSL)

## Quick Start

### Server

```bash
masque-tunnel server \
  --listen [::]:443 \
  --cert cert.pem \
  --key key.pem \
  --auth-token your-secret-token
```

### Client

```bash
masque-tunnel client \
  --listen 127.0.0.1:51820 \
  --proxy-url https://your-server.com \
  --target 10.0.0.1:51820 \
  --auth-token your-secret-token
```

This creates a local UDP endpoint at `127.0.0.1:51820` that tunnels all traffic through the MASQUE proxy to `10.0.0.1:51820`.

## CONNECT-IP (IP-layer VPN)

CONNECT-IP tunnels raw IP packets instead of a single UDP flow: the client
gets a TUN device with a proxy-assigned address, and anything routed into it
travels through the same QUIC/H3 transport. Both ends need root (TUN device
creation).

### Server

Enable CONNECT-IP by giving the server an address pool. The server takes each
pool's first host address for its own TUN device and assigns one `/32` (IPv4)
and/or `/128` (IPv6) per session from the rest. Pass `--ip-pool`,
`--ip6-pool`, or both for dual-stack:

```bash
sudo masque-tunnel server \
  --listen [::]:443 \
  --cert cert.pem --key key.pem \
  --auth-token your-secret-token \
  --ip-pool 10.99.0.0/24 \
  --ip6-pool fd00:99::/64
```

Each session then gets both an IPv4 and an IPv6 address, and the proxy
advertises a default route for each family it assigned.

Forwarding between the TUN device and the internet is the kernel's job.
On Linux:

```bash
sudo sysctl -w net.ipv4.ip_forward=1     # persist in /etc/sysctl.d/99-masque.conf
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo iptables  -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -s fd00:99::/64 -o eth0 -j MASQUERADE
# or with nftables:
#   nft add table ip nat
#   nft add chain ip nat postrouting { type nat hook postrouting priority srcnat \; }
#   nft add rule ip nat postrouting ip saddr 10.99.0.0/24 oifname eth0 masquerade
```

For IPv6 you would normally route a globally-routable prefix rather than NAT a
ULA (`fd00::/8`); the example uses a ULA pool because it needs no allocation.
Because the kernel routes the transited packets, TTL/hop-limit decrement,
fragmentation, and ICMP error generation follow normal router behavior. On top
of that, a packet too large for a single QUIC DATAGRAM gets an ICMP Packet Too
Big generated by masque itself at both ends (RFC 9484 §7.1).

### Client

```bash
sudo masque-tunnel client-ip \
  --proxy-url https://your-server.com \
  --auth-token your-secret-token
```

The client sends an extended CONNECT with `:protocol: connect-ip` to
`/.well-known/masque/ip/*/*/` (full tunnel), waits for the proxy's
`ADDRESS_ASSIGN` capsule, then brings up a TUN device with every assigned
address (IPv4 and/or IPv6). Route whatever you want through it:

```bash
# macOS
sudo route add -net 192.0.2.0/24 -interface utun6
# Linux
sudo ip route add 192.0.2.0/24 dev tun0
```

### Full tunnel

Pass `--redirect-gateway` and the client sets up the default route for you: it
pins a host route to the proxy via your physical gateway (so the tunnel doesn't
swallow its own QUIC packets), installs a split default (`0.0.0.0/1` +
`128.0.0.0/1`, and the IPv6 equivalents) toward the TUN, and reverts everything
on exit — including Ctrl-C, via a signal handler. Add `--dns` to route DNS
through the tunnel as well:

```bash
sudo masque-tunnel client-ip \
  --proxy-url https://your-server.com --auth-token your-secret-token \
  --redirect-gateway --dns 1.1.1.1
```

Routes are applied declaratively (RFC 9484 §4.7.3): each `ROUTE_ADVERTISEMENT`
is the complete set, so newly advertised ranges are installed and withdrawn
ranges removed. Address changes (`ADDRESS_ASSIGN`) are reconciled in place too
— across reassignments the client keeps the same TUN device and your routes,
adding or removing addresses rather than recreating the interface.

### MTU

Both TUN devices default to MTU **1280** (`--mtu` / `--ip-mtu`). The QUIC
DATAGRAM payload on the proxy path carries about 1300 bytes before path-MTU
discovery converges, so 1280 is the safe ceiling. A packet too large for one
DATAGRAM is not dropped: the tunnel replies with an ICMP Packet Too Big
(ICMPv4 Fragmentation Needed / ICMPv6 Packet Too Big, RFC 9484 §7.1) so the
source lowers its MTU, keeping Path MTU Discovery working.

## Usage

```
masque-tunnel <COMMAND>

Commands:
  client     Run as MASQUE CONNECT-UDP client
  client-ip  Run as MASQUE CONNECT-IP client (VPN over a local TUN device)
  server     Run as MASQUE proxy server (CONNECT-UDP always; CONNECT-IP with --ip-pool)
```

### Client Options

| Flag | Short | Description | Required |
|------|-------|-------------|----------|
| `--listen` | `-l` | Local UDP listen address | yes |
| `--proxy-url` | `-p` | MASQUE proxy server URL | yes |
| `--target` | `-t` | Target UDP endpoint (host:port) | yes |
| `--sni` | | TLS SNI override for domain fronting | no |
| `--auth-token` | | Bearer token for authentication | no |
| `--ca` | | CA certificate PEM for server verification | no |
| `--insecure` | | Skip server certificate verification | no |

### Client-IP Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--proxy-url` | `-p` | MASQUE proxy server URL | required |
| `--sni` | | TLS SNI override for domain fronting | none |
| `--auth-token` | | Bearer token for authentication | none |
| `--ca` | | CA certificate PEM for server verification | none |
| `--insecure` | | Skip server certificate verification | none |
| `--mtu` | | TUN device MTU | `1280` |
| `--tun-name` | | TUN device name (macOS: `utunN`) | automatic |
| `--redirect-gateway` | | Take over the default route for a full tunnel | off |
| `--dns` | | System DNS resolver(s) while the tunnel is up (repeatable) | none |

### Server Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--listen` | `-l` | Listen address | `[::]:443` |
| `--cert` | | TLS certificate PEM file | required |
| `--key` | | TLS private key PEM file | required |
| `--auth-token` | | Required Bearer token | none |
| `--ip-pool` | | Enable CONNECT-IP: IPv4 pool (CIDR) | disabled |
| `--ip6-pool` | | Enable CONNECT-IP: IPv6 pool (CIDR); combine with `--ip-pool` for dual-stack | disabled |
| `--ip-mtu` | | Server-side TUN device MTU | `1280` |
| `--ip-tun-name` | | Server-side TUN device name | automatic |

## Deployment

### TLS Certificate

```bash
# Self-signed (testing)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj '/CN=masque-proxy'

# Let's Encrypt (production)
sudo certbot certonly --standalone -d your-domain.com
```

### Firewall

```bash
# QUIC uses UDP, not TCP
sudo ufw allow 443/udp
```

### Tuning for High Throughput

The kernel UDP socket buffer defaults (`net.core.rmem_max` ≈ 208 KB on most Linux distros) are too small for sustained QUIC traffic and become the first bottleneck above ~100 Mbps. Raise them on **both** endpoints:

```bash
sudo sysctl -w net.core.rmem_max=67108864 net.core.rmem_default=16777216
sudo sysctl -w net.core.wmem_max=67108864 net.core.wmem_default=16777216
# Persist across reboots: drop the same lines into /etc/sysctl.d/99-masque.conf
```

QUIC starts with an initial MTU of 1350 bytes and grows via PMTUD on stable paths. When tunneling WireGuard, set the WireGuard interface MTU to **1280** so the outer encrypted UDP packet fits inside the QUIC DATAGRAM payload even before PMTUD converges. For CONNECT-IP, a packet too large for one DATAGRAM triggers an ICMP Packet Too Big back to the source (RFC 9484 §7.1) rather than a silent drop; lowering the WireGuard MTU still avoids the round trip entirely.

### systemd Service

```ini
# /etc/systemd/system/masque-tunnel.service
[Unit]
Description=MASQUE CONNECT-UDP Tunnel
After=network.target

[Service]
ExecStart=/usr/local/bin/masque-tunnel server \
  --listen [::]:443 \
  --cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
  --key /etc/letsencrypt/live/your-domain.com/privkey.pem \
  --auth-token your-secret-token
Restart=always
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

For a dual-stack CONNECT-IP proxy, add the pools, enable forwarding + NAT, and
grant `CAP_NET_ADMIN` for the TUN device:

```ini
[Service]
ExecStartPre=/sbin/sysctl -qw net.ipv4.ip_forward=1
ExecStartPre=/sbin/sysctl -qw net.ipv6.conf.all.forwarding=1
ExecStart=/usr/local/bin/masque-tunnel server \
  --listen [::]:443 \
  --cert /etc/letsencrypt/live/your-domain.com/fullchain.pem \
  --key /etc/letsencrypt/live/your-domain.com/privkey.pem \
  --auth-token your-secret-token \
  --ip-pool 10.99.0.0/24 \
  --ip6-pool fd00:99::/64
ExecStartPost=-/bin/sh -c 'iptables  -t nat -C POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables  -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE'
ExecStartPost=-/bin/sh -c 'ip6tables -t nat -C POSTROUTING -s fd00:99::/64 -o eth0 -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s fd00:99::/64 -o eth0 -j MASQUERADE'
Restart=always
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
```

The IPv6 pool above is a ULA masqueraded (NAT66) behind the host's global
address; if the host has a routed IPv6 prefix, use that as `--ip6-pool` and
drop the `ip6tables` rule.

## Apple Platform Integration

On Apple platforms (iOS / macOS / tvOS), you can use `NWConnection` with `ProxyConfiguration` to route UDP traffic through the MASQUE proxy natively — no client binary needed.

```swift
import Network

let proxyUrl = URL(string: "https://your-server.com")!
let parameters = NWParameters.udp

let relayHop = ProxyConfiguration.RelayHop(
    http3RelayEndpoint: .url(proxyUrl),
    additionalHTTPHeaderFields: ["proxy-authorization": "Bearer your-secret-token"]
)
let proxyConfig = ProxyConfiguration(relayHops: [relayHop])
let privacyContext = NWParameters.PrivacyContext(description: "MASQUE proxy")
privacyContext.proxyConfigurations = [proxyConfig]
parameters.setPrivacyContext(privacyContext)

let connection = NWConnection(host: "10.0.0.1", port: 51820, using: parameters)
connection.stateUpdateHandler = { state in
    print("Connection state: \(state)")
}
connection.start(queue: .global(qos: .userInitiated))
```

The system's Network framework handles the HTTP/3 CONNECT-UDP handshake, QUIC transport, and DATAGRAM framing automatically. All UDP packets sent through this `NWConnection` will be tunneled via the MASQUE proxy to the specified target endpoint.

## Build from Source

The QUIC/HTTP-3 stack is [quiche](https://github.com/cloudflare/quiche) +
[tokio-quiche](https://crates.io/crates/tokio-quiche), which compile BoringSSL
from source. That needs a C/C++ toolchain and CMake in addition to Rust:

```bash
# Debian/Ubuntu
sudo apt-get install -y clang cmake

cargo build --release
```

The release binary links libc dynamically (glibc); distribute the binary for
a matching libc, or ship a container image. A fully static musl build is
possible but requires a musl C/C++ cross-toolchain to build BoringSSL and
statically link the C++ runtime — it is not the default here.

## Architecture

```
src/
├── main.rs       # CLI entry point (clap subcommands)
├── client.rs     # CONNECT-UDP client: local UDP ↔ MASQUE DATAGRAM
├── ip_client.rs  # CONNECT-IP client: TUN ↔ MASQUE DATAGRAM, Happy Eyeballs, keepalive
├── server.rs     # QUIC/H3 server: request dispatch, CONNECT-UDP sessions
├── ip_server.rs  # CONNECT-IP server: shared TUN, address pool, routing
├── capsule.rs    # Capsule protocol (RFC 9297) + CONNECT-IP capsules (RFC 9484)
├── route.rs      # Client host-route takeover (--redirect-gateway), declarative reconcile
├── dns.rs        # Client system-DNS takeover (--dns)
├── icmp.rs       # ICMP Packet Too Big generation (RFC 9484 §7.1)
└── common.rs     # Shared: varint codec, datagram framing, path parsing
```

### Protocol Flow

```
WireGuard ──UDP──▶ masque-tunnel client ──QUIC/H3──▶ masque-tunnel server ──UDP──▶ WireGuard
           (local)                        (port 443)                        (target)
```

1. Client binds a local UDP socket and accepts WireGuard packets
2. Establishes QUIC connection to the proxy server (port 443)
3. Sends HTTP/3 extended CONNECT request (`:protocol: connect-udp`)
4. Path: `/.well-known/masque/udp/{target_host}/{target_port}/`
5. Server responds `200` and creates a UDP socket to the target
6. Bidirectional forwarding via QUIC DATAGRAM frames (RFC 9297)

For CONNECT-IP the flow differs after step 2: the client requests
`/.well-known/masque/ip/*/*/` with `:protocol: connect-ip`, the server
responds `200` followed by `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT`
capsules on the request stream, both ends bring up TUN devices, and complete
IP packets (Context ID 0) flow in QUIC DATAGRAM frames.

### Performance Optimizations

- **BBR2** congestion control (vs default Reno)
- **Pre-allocated receive buffers** — the read side reuses a fixed buffer per forwarding loop
- **Async target readers** — spawned tokio tasks for target→client direction
- **Non-blocking forwarding** — `try_send` on the data path drops instead of blocking when a queue is full

## License

BSD-2-Clause
