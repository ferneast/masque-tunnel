# masque-tunnel

A high-performance MASQUE tunnel — **CONNECT-UDP** ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)) and **CONNECT-IP** ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) — with client and server in a single binary.

Tunnels traffic through HTTP/3 (QUIC) DATAGRAM frames on port 443, making it indistinguishable from normal HTTPS traffic. CONNECT-UDP forwards a single UDP flow (ideal for wrapping WireGuard); CONNECT-IP is a full-tunnel VPN that carries arbitrary IP packets over a TUN device. Built on [quinn](https://github.com/quinn-rs/quinn) + [h3](https://github.com/hyperium/h3) with rustls/aws-lc-rs.

## Background

`masque-tunnel` was extracted from [Xlarva](https://xlarva.app/), a multi-platform WireGuard client for iOS, macOS, and tvOS. While building Xlarva's obfuscation features, we needed an RFC-compliant way to wrap WireGuard's UDP traffic inside an encrypted, indistinguishable-from-HTTPS transport. The popular [`wstunnel`](https://github.com/erebe/wstunnel) project covers TCP-style encapsulation over WebSockets, but it doesn't preserve UDP semantics — turning a UDP-only protocol like WireGuard into a TCP-over-TCP nightmare on lossy networks.

MASQUE solves exactly this: CONNECT-UDP ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)) carries UDP datagrams natively over HTTP/3 / QUIC, and CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)) carries whole IP packets — the same protocol family used by Apple iCloud Private Relay and Cloudflare WARP. We built this so any Xlarva user — or anyone who wants a self-hosted, RFC-standard alternative to closed proxy services — can stand up their own relay in minutes.

## Features

- **CONNECT-UDP ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298))** — tunnel a single UDP flow over HTTP/3 QUIC DATAGRAM frames (e.g. WireGuard obfuscation)
- **CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484))** — full-tunnel VPN over a TUN device, dual-stack (IPv4 + IPv6), with declarative address assignment and route advertisement capsules ([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297))
- **Client + Server** — single binary with `client` / `client-ip` / `server` subcommands
- **Obfuscation** — traffic appears as standard HTTPS/QUIC on port 443
- **Authentication** — optional Bearer token for client verification
- **Full-tunnel client extras** — `--redirect-gateway` to take over the default route, `--dns` to set system resolvers (both reverted on exit)
- **Happy Eyeballs ([RFC 8305](https://datatracker.ietf.org/doc/html/rfc8305))** — dual-stack clients race IPv4/IPv6 handshakes so a dead family never wedges connect
- **RFC-correct hop handling** — ICMP Packet Too Big on oversized packets and hop-count decrement on encapsulation ([RFC 9484 §7.1](https://datatracker.ietf.org/doc/html/rfc9484#section-7.1))
- **Auto-reconnect** — client reconnects with exponential backoff
- **Static binaries** — musl-linked, runs on any Linux (including RouterOS containers); iOS/tvOS static library for `NEPacketTunnelProvider`

## Quick Start

### CONNECT-UDP (single UDP flow, e.g. WireGuard)

Server:

```bash
masque-tunnel server \
  --listen [::]:443 \
  --cert cert.pem --key key.pem \
  --auth-token your-secret-token
```

Client — exposes a local UDP endpoint that tunnels to `10.0.0.1:51820` through the proxy:

```bash
masque-tunnel client \
  --listen 127.0.0.1:51820 \
  --proxy-url https://your-server.com \
  --target 10.0.0.1:51820 \
  --auth-token your-secret-token
```

### CONNECT-IP (full-tunnel VPN)

Server — hand out addresses from a pool and forward via the kernel (see [CONNECT-IP server setup](#connect-ip-server-setup) for forwarding + NAT):

```bash
masque-tunnel server \
  --listen [::]:443 \
  --cert cert.pem --key key.pem \
  --auth-token your-secret-token \
  --ip-pool 10.99.0.0/24 \
  --ip6-pool fd00:99::/64
```

Client — creates a TUN device with a proxy-assigned address and routes all traffic through it (needs root):

```bash
sudo masque-tunnel client-ip \
  --proxy-url https://your-server.com \
  --auth-token your-secret-token \
  --redirect-gateway
```

## Usage

```
masque-tunnel <COMMAND>

Commands:
  client     Run as MASQUE CONNECT-UDP client (local UDP socket)
  client-ip  Run as MASQUE CONNECT-IP client (full-tunnel VPN over a TUN device)
  server     Run as MASQUE proxy server (CONNECT-UDP always; CONNECT-IP with --ip-pool)
```

### `client` options (CONNECT-UDP)

| Flag | Short | Description | Required |
|------|-------|-------------|----------|
| `--listen` | `-l` | Local UDP listen address | yes |
| `--proxy-url` | `-p` | MASQUE proxy server URL | yes |
| `--target` | `-t` | Target UDP endpoint (host:port) | yes |
| `--sni` | | TLS SNI override for domain fronting | no |
| `--auth-token` | | Bearer token for authentication | no |
| `--ca` | | CA certificate PEM to verify the server | no |
| `--insecure` | | Skip server certificate verification | no |

### `client-ip` options (CONNECT-IP full tunnel)

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--proxy-url` | `-p` | MASQUE proxy server URL | required |
| `--sni` | | TLS SNI override | none |
| `--auth-token` | | Bearer token for authentication | none |
| `--ca` | | CA certificate PEM to verify the server | system roots |
| `--insecure` | | Skip server certificate verification | off |
| `--mtu` | | TUN device MTU (must fit a QUIC DATAGRAM) | `1280` |
| `--tun-name` | | TUN device name (Linux: any; macOS: `utunN`) | auto |
| `--redirect-gateway` | | Take over the host default route when the proxy advertises a full tunnel; reverted on exit | off |
| `--dns` | | System resolver(s) to install while up, restored on exit (repeatable) | none |

Server verification defaults to the system/Mozilla CA bundle, so a public ACME (Let's Encrypt) certificate is trusted out of the box; use `--ca` for a private CA or `--insecure` for self-signed testing.

### `server` options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--listen` | `-l` | Listen address | `[::]:443` |
| `--cert` | | TLS certificate PEM file | required |
| `--key` | | TLS private key PEM file | required |
| `--auth-token` | | Required Bearer token | none |
| `--ip-pool` | | Enable CONNECT-IP with this IPv4 pool (CIDR) | off |
| `--ip6-pool` | | Enable CONNECT-IP with this IPv6 pool (CIDR) | off |
| `--ip-mtu` | | MTU of the CONNECT-IP TUN device | `1280` |
| `--ip-tun-name` | | Name for the CONNECT-IP TUN device | auto |

CONNECT-UDP is always served. CONNECT-IP is enabled only when `--ip-pool` and/or `--ip6-pool` is given; without a pool, `connect-ip` requests are rejected.

## Deployment

### TLS Certificate

```bash
# Self-signed (testing — pair with the client's --insecure)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=masque-proxy'

# Let's Encrypt (production)
sudo certbot certonly --standalone -d your-domain.com
```

### Firewall

```bash
# QUIC uses UDP, not TCP
sudo ufw allow 443/udp
```

### CONNECT-IP server setup

A CONNECT-IP server routes client traffic to the internet through the kernel, so it needs IP forwarding and NAT for the pools. The kernel's forwarding also performs the [RFC 9484 §7.1](https://datatracker.ietf.org/doc/html/rfc9484#section-7.1) hop-count decrement for transited packets.

```bash
# Forwarding (both families)
sudo sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1

# NAT the pools out your uplink (replace eth0)
sudo iptables  -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -s fd00:99::/64  -o eth0 -j MASQUERADE
```

### Tuning for High Throughput

The kernel UDP socket buffer defaults (`net.core.rmem_max` ≈ 208 KB on most Linux distros) are too small for sustained QUIC traffic and become the first bottleneck above ~100 Mbps. Raise them on **both** endpoints:

```bash
sudo sysctl -w net.core.rmem_max=67108864 net.core.rmem_default=16777216
sudo sysctl -w net.core.wmem_max=67108864 net.core.wmem_default=16777216
# Persist across reboots: drop the same lines into /etc/sysctl.d/99-masque.conf
```

QUIC starts with an optimistic 1350-byte MTU and adapts via path MTU discovery. Set the tunneled interface (WireGuard MTU, or the CONNECT-IP `--mtu`) to **1280** so packets fit inside a QUIC DATAGRAM on typical paths; a packet too large for one datagram is answered with an ICMP Packet Too Big rather than dropped silently, but sizing it down avoids the round trip.

### systemd Service

CONNECT-UDP only:

```ini
# /etc/systemd/system/masque-tunnel.service
[Unit]
Description=MASQUE tunnel
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

For CONNECT-IP, add the pool flags to `ExecStart`, grant `CAP_NET_ADMIN` (for the TUN), and set up forwarding + NAT via `ExecStartPre`/`ExecStartPost`:

```ini
ExecStartPre=/sbin/sysctl -qw net.ipv4.ip_forward=1
ExecStartPre=/sbin/sysctl -qw net.ipv6.conf.all.forwarding=1
ExecStart=/usr/local/bin/masque-tunnel server \
  --listen [::]:443 --cert … --key … --auth-token … \
  --ip-pool 10.99.0.0/24 --ip6-pool fd00:99::/64
ExecStartPost=-/bin/sh -c 'iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o eth0 -j MASQUERADE'
ExecStartPost=-/bin/sh -c 'ip6tables -t nat -C POSTROUTING -s fd00:99::/64 -o eth0 -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s fd00:99::/64 -o eth0 -j MASQUERADE'
# …
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
```

## Apple Platform Integration

**CONNECT-UDP** — on Apple platforms you can route a UDP flow through the proxy natively with `NWConnection` + `ProxyConfiguration`, no client binary needed:

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
connection.start(queue: .global(qos: .userInitiated))
```

**CONNECT-IP** — the full-tunnel client is exposed as a C ABI (`src/ffi.rs`) for use inside a `NEPacketTunnelProvider`. The host hands the Rust core a `dup` of the provider's utun file descriptor via `masque_client_ip_start`, and programs `NEIPv4Settings` / routes / DNS from the assigned-address and route-advertisement callbacks; `masque_client_ip_stop` tears it down. Build the static library for the Apple targets (`crate-type = ["staticlib"]`) and wrap it in an xcframework.

## Build from Source

```bash
cargo build --release
```

The release binary is statically linked (musl) and optimized with LTO. The crate also builds a `staticlib` for the iOS/tvOS FFI.

> **Note:** the `h3` crate (0.0.8) is vendored under `vendor/h3` with a one-line patch (via `[patch.crates-io]`) that adds `connect-ip` to its `:protocol` pseudo-header enum — upstream only accepts `webtransport`/`connect-udp` and rejects `connect-ip` with `H3_MESSAGE_ERROR` before the request reaches the handler.

## Architecture

```
src/
├── main.rs          # CLI entry point (client / client-ip / server)
├── client.rs        # CONNECT-UDP client: local UDP ↔ QUIC DATAGRAM
├── ip_client.rs     # CONNECT-IP client: TUN ↔ QUIC DATAGRAM + capsules (full-tunnel VPN)
├── server.rs        # Server: auth + CONNECT-UDP forwarding + CONNECT-IP dispatch
├── ip_server.rs     # CONNECT-IP server: TUN, address pools, downstream routing
├── capsule.rs       # RFC 9297 capsule framing + RFC 9484 ADDRESS/ROUTE capsules
├── icmp.rs          # ICMP Packet Too Big generation (RFC 9484 §7.1)
├── route.rs         # Host route management (client full-tunnel redirect)
├── dns.rs           # System DNS takeover (client)
├── tun_platform.rs  # TUN backend (desktop: create; iOS/tvOS: adopt host fd)
├── ffi.rs           # C ABI for iOS/tvOS NEPacketTunnelProvider
└── common.rs        # varint/datagram codec, hop-limit decrement, path parsing
vendor/h3/           # h3 0.0.8 patched to accept the connect-ip :protocol
```

### CONNECT-UDP flow

```
WireGuard ──UDP──▶ client ──QUIC/H3──▶ server ──UDP──▶ target
           (local)          (port 443)          (e.g. WireGuard peer)
```

1. Client binds a local UDP socket and sends an HTTP/3 extended CONNECT (`:protocol = connect-udp`) with path `/.well-known/masque/udp/{host}/{port}/`.
2. Server replies `200`, opens a UDP socket to the target, and forwards bidirectionally over QUIC DATAGRAM frames (RFC 9297 quarter-stream-id + context-id).

### CONNECT-IP flow

```
apps ──▶ TUN ──▶ client ──QUIC/H3──▶ server ──▶ TUN ──▶ kernel forward + NAT ──▶ internet
             (IP packets)  (port 443)      (assigned pool)
```

1. Client sends an extended CONNECT (`:protocol = connect-ip`) with path `/.well-known/masque/ip/*/*/`.
2. Server replies `200` and, on the request stream, sends an unprompted `ADDRESS_ASSIGN` (a /32 and/or /128 from its pool) plus a `ROUTE_ADVERTISEMENT` for the default route (RFC 9484 capsules).
3. Client brings up a TUN with the assigned address; IP packets travel as QUIC DATAGRAMs (context-id 0), while capsules travel on the request stream.
4. The server writes upstream packets to a shared TUN (source-validated against the assigned address) and routes downstream packets by destination; the kernel handles forwarding, NAT, and the hop-count decrement.

## License

BSD-2-Clause
