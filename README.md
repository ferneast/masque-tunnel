# masque-tunnel

A high-performance MASQUE CONNECT-UDP (RFC 9298) tunnel — both client and server in a single binary.

Tunnels UDP traffic through HTTP/3 (QUIC) DATAGRAM frames on port 443, making it indistinguishable from normal HTTPS traffic. Designed for use as a VPN obfuscation layer (e.g., tunneling WireGuard).

## Features

- **RFC 9298 compliant** — CONNECT-UDP over HTTP/3 with QUIC DATAGRAM frames
- **Client + Server** — single binary with `client` / `server` subcommands
- **High throughput** — BBR2 congestion control, batched I/O, zero-copy forwarding
- **Obfuscation** — traffic appears as standard HTTPS/QUIC on port 443
- **Authentication** — optional Bearer token for client verification
- **SNI override** — supports domain fronting via custom TLS SNI
- **Auto-reconnect** — client automatically reconnects with exponential backoff
- **Static binaries** — musl-linked, runs on any Linux (including RouterOS containers)

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

## Usage

```
masque-tunnel <COMMAND>

Commands:
  client  Run as MASQUE CONNECT-UDP client
  server  Run as MASQUE CONNECT-UDP proxy server
```

### Client Options

| Flag | Short | Description | Required |
|------|-------|-------------|----------|
| `--listen` | `-l` | Local UDP listen address | yes |
| `--proxy-url` | `-p` | MASQUE proxy server URL | yes |
| `--target` | `-t` | Target UDP endpoint (host:port) | yes |
| `--sni` | | TLS SNI override for domain fronting | no |
| `--auth-token` | | Bearer token for authentication | no |

### Server Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--listen` | `-l` | Listen address | `[::]:443` |
| `--cert` | | TLS certificate PEM file | required |
| `--key` | | TLS private key PEM file | required |
| `--auth-token` | | Required Bearer token | none |

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
User=masque
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## Build from Source

```bash
cargo build --release
```

The release binary is statically linked (musl) and optimized with LTO.

## Architecture

```
src/
├── main.rs      # CLI entry point (clap subcommands)
├── client.rs    # QUIC/H3 client: local UDP ↔ MASQUE DATAGRAM
├── server.rs    # QUIC/H3 server: MASQUE DATAGRAM ↔ target UDP
└── common.rs    # Shared: varint codec, flush, constants
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

### Performance Optimizations

- **BBR2** congestion control (vs default Reno)
- **Batched I/O** — up to 64 packets per event loop iteration via `try_recv_from`
- **Pre-allocated buffers** — zero per-packet heap allocation in the forwarding path
- **Async target readers** — spawned tokio tasks for target→client direction
- **Non-blocking forwarding** — `try_send` / `try_send_to` on data path

## License

BSD-2-Clause
