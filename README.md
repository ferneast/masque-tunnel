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
- **Decoy site** — anything that is not an authenticated tunnel session is answered as an ordinary web server would, so an active probe sees a website rather than a proxy ([details](#decoy-site---masquerade-dir----masquerade-url))
- **Handshake that outgrows the first datagram** — the PQ key share pushes the ClientHello past one QUIC Initial, so the SNI is not in the datagram the GFW's QUIC filter inspects ([details](#sni-placement-in-the-handshake))
- **Authentication** — optional Bearer token for client verification, compared in constant time
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
| `--ip-routes-file` | | File of routes to advertise (one CIDR per line) — split tunnel | full tunnel |
| `--dns-assign` | | DNS resolver(s) to advertise to clients (repeatable) | none |
| `--ip-allow-private` | | Let clients reach private ranges (RFC 1918/CGN/ULA) behind the server | blocked |
| `--masquerade-dir` | | Serve this directory to non-tunnel requests | built-in page |
| `--masquerade-url` | | Redirect (302) non-tunnel requests here instead | off |
| `--server-header` | | Value for the `Server` response header, e.g. `nginx` | none sent |

CONNECT-UDP is always served. CONNECT-IP is enabled only when `--ip-pool` and/or `--ip6-pool` is given; without a pool, `connect-ip` requests are rejected.

### Decoy site (`--masquerade-dir` / `--masquerade-url`)

Every request that does not become an authenticated tunnel session is answered as an ordinary web server would. This matters because a proxy that replies `405 Method Not Allowed` to a plain `GET /`, or `407 Proxy Authentication Required` to a wrong token, has identified itself to anyone who asks — and an IP blocklisting, unlike SNI-based filtering, does not expire. The same reasoning drives Trojan's nginx fallback, Hysteria 2's `masquerade:` block, and VLESS+REALITY.

Three modes:

- **`--masquerade-dir <path>`** — serve files from a directory, `index.html` for directory paths. Path traversal is refused in every encoding, and files over 8 MB are treated as absent.
- **`--masquerade-url <url>`** — answer everything with a `302` to an absolute URL.
- **neither** — a built-in placeholder page at `/` and a `404` elsewhere.

Two properties are load-bearing and covered by `tests/masquerade.rs`: a rejected tunnel request and a plain fetch of the same path produce **byte-identical** responses, and no response names this product. Set `--server-header` to whatever the decoy content should look like it is being served by; it is applied to tunnel responses too, so the two cannot be told apart by it.

The tradeoff for operators: a wrong `--auth-token` no longer produces a distinct error. The client reports the status it got and lists the possible causes, but the server cannot say "bad token" without also saying it to a prober. Server logs still record `Auth failed, serving decoy`.

### SNI placement in the handshake

A QUIC Initial packet is encrypted with keys derived from the destination connection ID and a fixed, published salt, so any observer on the path can decrypt it and read the SNI. The GFW has done exactly this at national scale since August 2024 ([USENIX Security 2025](https://gfw.report/publications/usenixsecurity25/en/)); a match drops every packet of the `(src IP, dst IP, dst port)` triple for 180 seconds, which presents as "the tunnel died and came back a few minutes later".

That filter inspects only the **first datagram** of a flow and does not reassemble a ClientHello spread across several. This build enables rustls's `prefer-post-quantum`, which offers `X25519MLKEM768` first; its ~1216-byte key share pushes the ClientHello over the ~1200-byte Initial budget, so the handshake occupies two datagrams and the SNI is not in the one being read. `tests/initial_flight.rs` asserts the spill, and fails if a dependency change quietly shrinks the ClientHello again.

Two caveats worth being clear about. This exploits an implementation shortcut, not a protocol property — it holds until the filter learns to reassemble. And the GFW's QUIC list is a *blocklist*: a domain that was never listed was never being filtered on SNI, so this is insurance against your domain being added, not necessarily a fix for a connection failing today. It also costs ~1.2 KB per handshake, and does nothing about an IP-level block.

### DNS assignment (`--dns-assign`)

RFC 9484 assigns addresses and routes but no resolver, so a CONNECT-IP client otherwise needs `--dns` to know what DNS to use. `--dns-assign <addr>` (repeatable, IPv4/IPv6) makes the server advertise resolvers in a **DNS_ASSIGN capsule** ([draft-ietf-masque-connect-ip-dns](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ip-dns/)); a client that wasn't given its own `--dns` adopts them automatically. This is a minimal profile (plain Do53 addresses — no encrypted-DNS/SVCB or search domains yet).

The draft has no IANA-assigned capsule type yet, so both ends hardcode a **provisional codepoint `0x1ACE_79EC`** (`CAPSULE_DNS_ASSIGN` in `src/capsule.rs`). This is a private-use value picked to avoid colliding with RFC 9484's registered types (`0x00`–`0x03`); it **must** be changed to the assigned codepoint once the draft is published as an RFC, and it is not interoperable with any other implementation until then.

### Split tunnel (`--ip-routes-file`)

By default the server advertises a full tunnel (`0.0.0.0/0` and/or `::/0`). To route only specific prefixes through the tunnel, pass `--ip-routes-file` with one CIDR per line (`#` comments and blank lines ignored, IPv4/IPv6 mixed):

```
# only these go through the tunnel
10.8.0.0/16
172.16.0.0/12
2001:db8:abcd::/48
```

The server sends these as the RFC 9484 ROUTE_ADVERTISEMENT (each advertisement is the complete set, per §4.7.3). The client installs exactly these prefixes as direct routes via the TUN and leaves the host's default route untouched — so a split tunnel needs no `--redirect-gateway`. The file is read once at startup; a route with no matching assigned address family is skipped.

### Destination filtering

Besides source validation (a packet whose source is not the session's assigned address is dropped — RFC 9484 §11 / BCP 38), the server filters upstream packets by destination before they reach the TUN:

- **Always dropped**: loopback, link-local (`169.254.0.0/16` incl. the cloud metadata service `169.254.169.254`, `fe80::/10`), the Alibaba Cloud metadata address `100.100.100.200`, multicast, broadcast, unspecified, `0.0.0.0/8`, and IPv4-mapped IPv6.
- **Dropped by default, opt-in via `--ip-allow-private`**: private ranges behind the server — RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), CGN `100.64.0.0/10`, and IPv6 ULA `fc00::/7`. This keeps tunneled clients out of the server's VPC/LAN through NAT unless LAN access is intended.
- **Always reachable**: the tunnel's own address pools (server gateway, other clients) and any `--dns-assign` resolvers, even when they sit in private space.

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
2. Server replies `200`; the client then sends an `ADDRESS_REQUEST` (one no-preference entry per family) on the request stream.
3. Server answers with an `ADDRESS_ASSIGN` (a /32 and/or /128 from its pool, echoing the Request IDs) plus a `ROUTE_ADVERTISEMENT` for the default route (RFC 9484 capsules).
4. Client brings up a TUN with the assigned address; IP packets travel as QUIC DATAGRAMs (context-id 0), while capsules travel on the request stream.
5. The server writes upstream packets to a shared TUN (source-validated against the assigned address) and routes downstream packets by destination; the kernel handles forwarding, NAT, and the hop-count decrement.

## Standards conformance

The CONNECT-IP implementation targets the full-tunnel VPN case. It implements
extended CONNECT with `:protocol = connect-ip`, the Capsule Protocol
([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297)) with unknown-type
skipping, the `ADDRESS_ASSIGN` / `ADDRESS_REQUEST` / `ROUTE_ADVERTISEMENT`
capsules ([RFC 9484 §4.7](https://datatracker.ietf.org/doc/html/rfc9484#section-4.7)),
IP packets in HTTP Datagrams (context ID 0), dual-stack addressing,
source-address validation of upstream packets
([§8.1](https://datatracker.ietf.org/doc/html/rfc9484#section-8.1)), and the ICMP
Packet Too Big / hop-limit handling of
[§7.1](https://datatracker.ietf.org/doc/html/rfc9484#section-7.1).

Relative to RFC 9484, the following is **not** implemented:

- **Scoped requests.** Only the full-tunnel wildcard request
  (`/.well-known/masque/ip/*/*/`, target and IP protocol both `*`) is served. A
  request naming a specific target IP or IP protocol is rejected with `400`
  ([§4.1](https://datatracker.ietf.org/doc/html/rfc9484#section-4.1) permits a
  proxy to refuse these). There is no per-flow or per-protocol packet filtering.
- **Client-requested specific addresses.** The server pre-assigns one host
  address per family, sequentially from its pool, and answers `ADDRESS_REQUEST`
  only from that pre-assigned set. A request for a specific address the client
  was not already assigned — or for a non-host prefix length — is refused with an
  all-zero `AssignedAddress`. There is no on-demand allocation or renumbering.
- **Per-protocol routes.** `ROUTE_ADVERTISEMENT` always uses IP Protocol `0`
  (all protocols); the per-protocol scoping the capsule allows is not produced.
- **Bidirectional / client-as-router.** The client only consumes
  `ADDRESS_ASSIGN` and `ROUTE_ADVERTISEMENT`; it never advertises routes to the
  server and ignores an inbound `ADDRESS_REQUEST`. The symmetric site-to-site
  model (either endpoint routing on the other's behalf) is not implemented.
- **ECN.** ECN bits are not mapped between the inner IP packet and the outer
  QUIC datagram ([RFC 6040](https://datatracker.ietf.org/doc/html/rfc6040)).

**DNS assignment** is a separate, non-RFC extension via
[draft-ietf-masque-connect-ip-dns](https://datatracker.ietf.org/doc/draft-ietf-masque-connect-ip-dns/)
using a provisional capsule codepoint — see
[DNS assignment](#dns-assignment---dns-assign) above.

## License

BSD-2-Clause
