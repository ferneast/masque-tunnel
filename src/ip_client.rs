//! CONNECT-IP client (RFC 9484) on the quinn / h3 stack.
//!
//! Tunnels IP packets between a local TUN device and a MASQUE proxy. The TUN
//! device is created only after the proxy sends ADDRESS_ASSIGN, so the
//! interface always carries the proxy-assigned address(es). Across reconnects
//! the device is kept if the assignment is unchanged, preserving any routes the
//! operator added on top of it. Capsules arrive on the CONNECT-IP request
//! stream body (h3 DATA frames); IP packets travel on raw QUIC DATAGRAMs with
//! the RFC 9297 quarter-stream-id prefix and a context ID of 0.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use tun_rs::AsyncDevice;

use crate::capsule::*;
use crate::client::SkipServerVerification;
use crate::common::*;

/// CONNECT-IP client configuration parsed from CLI arguments.
pub struct IpClientConfig {
    pub proxy_url: String,
    pub sni: Option<String>,
    pub auth_token: Option<String>,
    pub insecure: bool,
    pub ca: Option<String>,
    /// MTU for the TUN device. Must not exceed what a QUIC DATAGRAM on the
    /// proxy path can carry (~1300 bytes with the default transport tuning).
    pub mtu: u16,
    pub tun_name: Option<String>,
    /// Take over the host default route when the proxy advertises a full tunnel.
    pub redirect_gateway: bool,
    /// System DNS resolver(s) to install while the tunnel is up (empty = off).
    pub dns: Vec<std::net::IpAddr>,
    /// Adopt the host-provided TUN fd in this slot (from
    /// `NEPacketTunnelProvider` on iOS/tvOS/macOS) instead of creating a device
    /// with tun-rs. When set, the device is host-managed: the host also
    /// programs its addresses, so the client never runs tun-rs address
    /// operations on it. The host may push a replacement fd into the slot at
    /// any time (see `TunFdSlot`).
    pub tun_fd: Option<std::sync::Arc<TunFdSlot>>,
    /// Host callbacks that program the platform config the Rust core does not
    /// do itself (iOS/tvOS: `NEIPv4Settings` / routes / DNS). `None` on desktop,
    /// where the client configures the TUN, routes, and DNS directly.
    pub events: Option<std::sync::Arc<dyn ClientEvents>>,
    /// Cumulative tunneled-byte counters the host may poll (FFI statistics).
    pub stats: Option<std::sync::Arc<TunnelStats>>,
    /// Host signal to drop the current connection and reconnect immediately
    /// (e.g. the iOS provider detected a network interface change), bypassing
    /// the QUIC idle-timeout wait. `None` on desktop.
    pub reconnect: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// Host signal to shut the client down gracefully: the active QUIC
    /// connection is closed (sending CONNECTION_CLOSE) so the proxy releases the
    /// assigned address immediately instead of waiting out its idle timeout,
    /// then `run` returns. `None` on desktop, where SIGINT/SIGTERM stops it.
    pub shutdown: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// Operator-preferred tunnel addresses for the interactive ADDRESS_REQUEST
    /// (RFC 9484 §4.7.2), used only while this client holds no address yet — the
    /// cold start before any ADDRESS_ASSIGN, where there is nothing to prefer.
    /// Empty (the default) keeps requesting the all-zero "no preference" address
    /// on a fresh tunnel. Otherwise the first entry of each IP family (one IPv4,
    /// one IPv6) seeds that family's request, so a proxy that honors preferences
    /// can hand back a stable IP from the very first connect. Once an address is
    /// assigned it is held on the TUN binding and always takes precedence.
    pub preferred_addresses: Vec<IpAddr>,
}

/// Cumulative tunneled traffic since start: `tx` counts IP bytes sent to the
/// proxy, `rx` counts IP bytes delivered to the TUN. Survives reconnects.
#[derive(Default)]
pub struct TunnelStats {
    pub tx: std::sync::atomic::AtomicU64,
    pub rx: std::sync::atomic::AtomicU64,
}

/// Host-updatable TUN fd for host-managed devices. On macOS, applying the real
/// tunnel settings can rebuild the utun and re-point the packet flow at a new
/// interface, invalidating the fd handed to start — the host then pushes a
/// replacement fd here and the forwarding loop swaps its device in place
/// without dropping the QUIC connection.
pub struct TunFdSlot {
    fd: std::sync::atomic::AtomicI32,
    changed: tokio::sync::Notify,
}

impl TunFdSlot {
    pub fn new(fd: std::os::fd::RawFd) -> Self {
        Self {
            fd: std::sync::atomic::AtomicI32::new(fd),
            changed: tokio::sync::Notify::new(),
        }
    }

    /// Replace the fd (ownership transfers to the tunnel) and wake the
    /// forwarding loop so it adopts the new device.
    pub fn replace(&self, fd: std::os::fd::RawFd) {
        self.fd.store(fd, std::sync::atomic::Ordering::Release);
        self.changed.notify_one();
    }

    fn current(&self) -> std::os::fd::RawFd {
        self.fd.load(std::sync::atomic::Ordering::Acquire)
    }

    async fn changed(&self) {
        self.changed.notified().await
    }
}

/// Await a host fd replacement, or pend forever for self-managed devices.
async fn wait_tun_fd_change(slot: Option<&Arc<TunFdSlot>>) {
    match slot {
        Some(s) => s.changed().await,
        None => std::future::pending().await,
    }
}

/// Host-side configuration callbacks. On iOS/tvOS the `NEPacketTunnelProvider`
/// uses these to program addresses and routes/DNS from the proxy's capsules; on
/// desktop they are unset and the client programs everything itself.
pub trait ClientEvents: Send + Sync {
    /// The complete assigned address set (RFC 9484 ADDRESS_ASSIGN).
    fn addresses_assigned(&self, addrs: &[(IpAddr, u8)]);
    /// The advertised route set (RFC 9484 ROUTE_ADVERTISEMENT).
    fn routes_advertised(&self, ranges: &[crate::capsule::IpAddressRange]);
    /// Server-assigned DNS resolvers (draft-ietf-masque-connect-ip-dns).
    /// Default: ignore — a host that does not program DNS from capsules (e.g.
    /// one relying on the platform default) can leave this unimplemented.
    fn dns_assigned(&self, _servers: &[IpAddr]) {}
}

/// The active TUN device plus the assignment it was configured with. `fd` is
/// the adopted host fd (`None` for self-managed tun-rs devices), used to skip
/// re-adopting a fd the device already owns.
struct TunBinding {
    dev: Arc<AsyncDevice>,
    addrs: Vec<(IpAddr, u8)>,
    fd: Option<std::os::fd::RawFd>,
}

/// Await the host's immediate-reconnect signal, or pend forever when none is
/// wired (desktop CLI), so the `select!` arm simply never fires there.
async fn wait_reconnect(notify: Option<&std::sync::Arc<tokio::sync::Notify>>) {
    match notify {
        Some(n) => n.notified().await,
        None => std::future::pending().await,
    }
}

/// Await the host's graceful-shutdown signal, or pend forever when none is
/// wired (desktop CLI, which stops on SIGINT/SIGTERM instead). Only one waiter
/// observes this at a time (the active `run_tunnel`, else the reconnect
/// backoff), so a single `notify_one` from the host is never missed.
async fn wait_shutdown(notify: Option<&std::sync::Arc<tokio::sync::Notify>>) {
    match notify {
        Some(n) => n.notified().await,
        None => std::future::pending().await,
    }
}

/// Why `run_tunnel` returned. Any error means the tunnel dropped and should be
/// retried; `Ok(Shutdown)` means the host asked to stop and the connection has
/// already been closed gracefully, so the reconnect loop must exit.
enum TunnelExit {
    Shutdown,
}

/// Run the MASQUE CONNECT-IP client with automatic reconnection.
pub async fn run(config: IpClientConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(&config.proxy_url)?;
    let proxy_host = url.host_str().ok_or("missing host in proxy URL")?.to_string();
    let proxy_port = url.port().unwrap_or(443);
    let sni = config
        .sni
        .clone()
        .unwrap_or_else(|| unbracket_host(&proxy_host).to_string());

    log::info!(
        "[client] CONNECT-IP mode, proxy={proxy_host}:{proxy_port} mtu={}",
        config.mtu
    );

    // The quinn client config (TLS + transport) is stable across reconnects.
    let client_config = build_client_config(&config)?;

    let mut tun: Option<TunBinding> = None;
    let mut routes = crate::route::RouteSet::new();
    let mut dns = crate::dns::DnsGuard::new(config.dns.clone());

    enum Step {
        Reconnect,
        Signaled,
        Shutdown,
    }
    let reconnect = async {
        let mut backoff_ms = 500u64;
        loop {
            // Set by run_tunnel once CONNECT-IP is established, so a drop after a
            // healthy session restarts backoff from the floor instead of
            // inheriting the growth from an earlier outage.
            let mut established = false;
            // Race the tunnel against an external immediate-reconnect signal.
            // The host (iOS provider) fires it the instant the network path
            // changes, so a Wi-Fi→cellular switch reconnects at once instead of
            // waiting out the ~30s QUIC idle timeout on the dead socket.
            // run_tunnel itself observes the shutdown signal (to close the
            // connection gracefully), so it is not raced here.
            let step = tokio::select! {
                res = run_tunnel(
                    &config, &client_config, &proxy_host, proxy_port, &sni, &mut tun, &mut routes,
                    &mut dns, &mut established,
                ) => {
                    if established {
                        backoff_ms = 500;
                    }
                    match res {
                        Ok(TunnelExit::Shutdown) => Step::Shutdown,
                        Err(e) => {
                            log::warn!("[client] connection lost: {e}, reconnecting in {backoff_ms}ms");
                            Step::Reconnect
                        }
                    }
                }
                _ = wait_reconnect(config.reconnect.as_ref()) => {
                    log::info!("[client] immediate reconnect requested (network change)");
                    Step::Signaled
                }
            };
            match step {
                // Graceful shutdown: the connection is already closed; stop.
                Step::Shutdown => break,
                Step::Signaled => {
                    // New path is up — reconnect right away with no backoff,
                    // binding a fresh socket on the new default interface.
                    backoff_ms = 500;
                    continue;
                }
                Step::Reconnect => {}
            }
            // Interruptible backoff: a shutdown during the wait must return
            // promptly instead of blocking the host's stop for up to the backoff.
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                _ = wait_shutdown(config.shutdown.as_ref()) => break,
            }
            backoff_ms = (backoff_ms * 2).min(30_000);
        }
    };

    // Run until a shutdown signal so route cleanup runs on Ctrl-C, instead of
    // leaving the host with a default route pointing at a torn-down TUN.
    tokio::select! {
        _ = reconnect => {}
        _ = shutdown_signal() => log::info!("[client] shutdown signal received, restoring routes"),
    }
    Ok(())
}

/// Resolve when the process is asked to terminate (SIGINT/SIGTERM on Unix,
/// Ctrl-C elsewhere), so route and TUN cleanup run on the way out.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) {
            (Ok(mut term), Ok(mut intr)) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = intr.recv() => {}
                }
            }
            _ => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Build the quinn client config: TLS trust (system roots by default, custom CA
/// with `--ca`, or no verification with `--insecure`) plus transport tuning
/// (optimistic 1350 initial MTU, large datagram buffers, BBR, 30s idle).
fn build_client_config(
    config: &IpClientConfig,
) -> Result<quinn::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut crypto = if config.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else if let Some(ca_path) = &config.ca {
        let file = std::fs::File::open(ca_path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut reader) {
            roots.add(cert?)?;
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        // Default: the Mozilla CA bundle (webpki-roots), which includes the
        // ISRG roots real ACME/Let's Encrypt certificates chain to — so iOS
        // connecting to a public masque host verifies without platform glue.
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    // Allow 0-RTT on reconnect: the shared client config's rustls session store
    // persists tickets across reconnects, so a resumed handshake sends the
    // CONNECT-IP request as early data and reaches address assignment one RTT
    // sooner. quinn transparently falls back to 1-RTT if the server rejects it.
    crypto.enable_early_data = true;

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1350);
    transport.datagram_receive_buffer_size(Some(8_000_000));
    transport.datagram_send_buffer_size(8_000_000);
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    // quinn PING frames keep an idle tunnel under max_idle_timeout, replacing the
    // app-level keepalive datagram the forwarding loop used to send.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    client_config.transport_config(Arc::new(transport));
    Ok(client_config)
}

/// Bind a quinn endpoint for one address family, with the shared client config.
fn make_endpoint(
    bind: &str,
    client_config: &quinn::ClientConfig,
) -> Result<quinn::Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    let mut ep = quinn::Endpoint::client(bind.parse()?)?;
    ep.set_default_client_config(client_config.clone());
    Ok(ep)
}

/// Happy Eyeballs (RFC 8305): interleave address families and start a handshake
/// every 250ms without waiting for the previous to fail, returning the first
/// connection that completes with its winning address. `ep_v4`/`ep_v6` are the
/// long-lived per-family endpoints (kept alive by the caller).
async fn establish_connection(
    addrs: Vec<SocketAddr>,
    sni: &str,
    ep_v4: Option<&quinn::Endpoint>,
    ep_v6: Option<&quinn::Endpoint>,
) -> Result<(quinn::Connection, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
    let mut pending = interleave_families(addrs).into_iter();
    let mut running = FuturesUnordered::new();
    let mut pending_done = false;
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let mut next_at = tokio::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            Some(res) = running.next() => match res {
                Ok(win) => return Ok(win),
                Err(e) => last_err = Some(e),
            },
            _ = tokio::time::sleep_until(next_at), if !pending_done => match pending.next() {
                Some(addr) => {
                    let ep = if addr.is_ipv4() { ep_v4 } else { ep_v6 };
                    if let Some(ep) = ep {
                        let ep = ep.clone();
                        let sni = sni.to_string();
                        running.push(async move {
                            let connecting = ep.connect(addr, &sni)?;
                            // Resume with 0-RTT when a cached ticket lets us;
                            // otherwise complete the full handshake. Only the
                            // replay-safe CONNECT-IP request rides as early data
                            // — IP datagrams wait for the post-handshake address
                            // assignment.
                            let conn = match connecting.into_0rtt() {
                                Ok((conn, accepted)) => {
                                    log::info!("[client] resuming with 0-RTT to {addr}");
                                    tokio::spawn(async move {
                                        if accepted.await {
                                            log::info!("[client] 0-RTT accepted by server");
                                        } else {
                                            log::info!("[client] 0-RTT rejected, fell back to 1-RTT");
                                        }
                                    });
                                    conn
                                }
                                Err(connecting) => connecting.await?,
                            };
                            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((conn, addr))
                        });
                    }
                    next_at = tokio::time::Instant::now() + ATTEMPT_DELAY;
                }
                None => pending_done = true,
            },
        }
        if pending_done && running.is_empty() {
            return Err(last_err.unwrap_or_else(|| "no proxy addresses to connect to".into()));
        }
    }
}

/// Order addresses for Happy Eyeballs: keep each family's system (RFC 6724)
/// order, but alternate families starting with whichever the system preferred.
fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let v6_first = addrs.first().map(|a| a.is_ipv6()).unwrap_or(false);
    let v6: VecDeque<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv6()).collect();
    let v4: VecDeque<SocketAddr> = addrs.iter().copied().filter(|a| a.is_ipv4()).collect();
    let mut out = Vec::with_capacity(addrs.len());
    let (mut first, mut second) = if v6_first { (v6, v4) } else { (v4, v6) };
    while !first.is_empty() || !second.is_empty() {
        if let Some(a) = first.pop_front() {
            out.push(a);
        }
        std::mem::swap(&mut first, &mut second);
    }
    out
}

/// The address to request for one family in the interactive ADDRESS_REQUEST
/// (RFC 9484 §4.7.2). Prefer the address already `held` on the TUN binding —
/// present on reconnects, keeping the tunnel IP stable. When nothing is held
/// yet (cold start), use the operator-configured `preferred` address if it
/// belongs to this family, else the all-zero `unspecified` "no preference"
/// sentinel (whose family also selects which family this call is resolving).
fn request_address(held: Option<IpAddr>, preferred: Option<IpAddr>, unspecified: IpAddr) -> IpAddr {
    if let Some(addr) = held {
        return addr;
    }
    match preferred {
        Some(p) if p.is_ipv4() == unspecified.is_ipv4() => p,
        _ => unspecified,
    }
}

/// One event handled by the forwarding loop, collected as an owned value so the
/// borrows taken inside `select!` end before we touch `tun`.
enum Event {
    /// A DATA-frame chunk of capsule bytes, or `None` when the stream closes.
    Capsule(Option<Bytes>),
    CapsuleErr(String),
    /// A downstream QUIC DATAGRAM, or `None` when the connection closes.
    Datagram(Option<Bytes>),
    Tun(std::io::Result<usize>),
    /// The host pushed a replacement TUN fd into the slot.
    TunFdChanged,
    AssignTimeout,
    /// The host asked to stop; close the connection gracefully and exit.
    Shutdown,
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    config: &IpClientConfig,
    client_config: &quinn::ClientConfig,
    proxy_host: &str,
    proxy_port: u16,
    sni: &str,
    tun: &mut Option<TunBinding>,
    routes: &mut crate::route::RouteSet,
    dns: &mut crate::dns::DnsGuard,
    established: &mut bool,
) -> Result<TunnelExit, Box<dyn std::error::Error + Send + Sync>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((unbracket_host(proxy_host), proxy_port))
        .await?
        .collect();
    if addrs.is_empty() {
        return Err(format!("DNS resolution failed for {proxy_host}:{proxy_port}").into());
    }

    // Per-family endpoints, kept alive for the whole tunnel so the winning
    // connection's socket outlives the Happy Eyeballs race.
    let ep_v4 = if addrs.iter().any(|a| a.is_ipv4()) {
        Some(make_endpoint("0.0.0.0:0", client_config)?)
    } else {
        None
    };
    let ep_v6 = if addrs.iter().any(|a| a.is_ipv6()) {
        Some(make_endpoint("[::]:0", client_config)?)
    } else {
        None
    };

    // A shutdown during the handshake needs no graceful close (no address is
    // assigned yet); just stop, dropping the in-flight connect attempts.
    let (conn, winning) = tokio::select! {
        r = establish_connection(addrs, sni, ep_v4.as_ref(), ep_v6.as_ref()) => r?,
        _ = wait_shutdown(config.shutdown.as_ref()) => return Ok(TunnelExit::Shutdown),
    };
    let proxy_ip = winning.ip();
    log::info!("[client] QUIC connected to {winning}");

    // IP packets ride raw QUIC DATAGRAMs; the h3 layer carries only the
    // CONNECT-IP request/response stream (and its capsule body).
    let dgram_conn = conn.clone();
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(h3_conn)
        .await?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Full-tunnel CONNECT-IP request: target and ipproto are both the wildcard,
    // which RFC 9484 Errata ID 8444 requires be percent-encoded as `%2A` (not a
    // literal `*`) in the URI template expansion.
    let path = format!("{CONNECT_IP_PATH}/%2A/%2A/");
    let uri: http::Uri = format!("https://{proxy_host}{path}").parse()?;
    let protocol: h3::ext::Protocol = "connect-ip".parse().map_err(|_| "invalid protocol")?;
    let mut req_builder = http::Request::builder()
        .method("CONNECT")
        .uri(uri)
        .header("capsule-protocol", "?1")
        .header("user-agent", IDENT);
    if let Some(token) = &config.auth_token {
        req_builder = req_builder.header("proxy-authorization", format!("Bearer {token}"));
    }
    let req = req_builder.extension(protocol).body(())?;

    let mut stream = send_request.send_request(req).await?;
    let resp = stream.recv_response().await?;
    if resp.status() != http::StatusCode::OK {
        return Err(format!("CONNECT-IP rejected: status {}", resp.status()).into());
    }
    if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
        log::info!("[client] proxy server: {server}");
    }

    // The raw QUIC stream ID feeds the DATAGRAM quarter-stream-id (id/4).
    let quic_stream_id = stream.id().index() * 4;
    log::info!("[client] CONNECT-IP established (stream_id={quic_stream_id})");
    // The server accepted CONNECT-IP: this attempt genuinely connected, so the
    // reconnect loop resets its backoff floor.
    *established = true;

    // Interactive assignment (RFC 9484 §4.7.2): request one address per family.
    // The address currently held on the TUN binding is requested so the proxy
    // keeps this client's tunnel IP stable across reconnects — avoiding a TUN
    // renumber and keeping both views in sync even if an ADDRESS_ASSIGN is lost.
    // On the cold start, before any assignment, nothing is held: fall back to the
    // operator-configured preferred address (if any, and of the right family) so
    // a fresh tunnel can still request a stable IP; otherwise send the all-zero
    // "no preference" sentinel, which an older proxy simply answers with its own
    // choice at Request ID 0. A held address always wins over the configured hint.
    let held_v4 = tun
        .as_ref()
        .and_then(|b| b.addrs.iter().find(|(a, _)| a.is_ipv4()).map(|(a, _)| *a));
    let held_v6 = tun
        .as_ref()
        .and_then(|b| b.addrs.iter().find(|(a, _)| a.is_ipv6()).map(|(a, _)| *a));
    // The configured list may carry both families; each request slot takes the
    // first entry of its own family (extra same-family entries are ignored — the
    // request has one slot per family).
    let pref_v4 = config.preferred_addresses.iter().copied().find(|a| a.is_ipv4());
    let pref_v6 = config.preferred_addresses.iter().copied().find(|a| a.is_ipv6());
    let req_v4 = request_address(held_v4, pref_v4, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let req_v6 = request_address(held_v6, pref_v6, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    stream
        .send_data(encode_address_request(&[
            RequestedAddress {
                request_id: 1,
                addr: req_v4,
                prefix_len: 32,
            },
            RequestedAddress {
                request_id: 2,
                addr: req_v6,
                prefix_len: 128,
            },
        ]))
        .await?;
    log::debug!("[client] sent ADDRESS_REQUEST (v4={req_v4}, v6={req_v6})");

    let mut parser = CapsuleParser::default();
    let mut pkt_buf = vec![0u8; config.mtu.max(1280) as usize + 64];
    // The proxy must assign an address promptly on a fresh tunnel; reconnect if
    // none arrives. Once any address has been assigned, an empty ADDRESS_ASSIGN
    // (withdraw-all, RFC 9484 §4.7.1) is legal and must not trip the deadline.
    let mut ever_assigned = tun.is_some();
    let assign_deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    loop {
        let event = tokio::select! {
            d = stream.recv_data() => match d {
                Ok(Some(mut b)) => Event::Capsule(Some(b.copy_to_bytes(b.remaining()))),
                Ok(None) => Event::Capsule(None),
                Err(e) => Event::CapsuleErr(e.to_string()),
            },
            dg = dgram_conn.read_datagram() => match dg {
                Ok(b) => Event::Datagram(Some(b)),
                Err(_) => Event::Datagram(None),
            },
            r = async {
                match tun.as_ref() {
                    Some(b) => b.dev.recv(&mut pkt_buf).await,
                    None => std::future::pending().await,
                }
            } => Event::Tun(r),
            _ = wait_tun_fd_change(config.tun_fd.as_ref()) => Event::TunFdChanged,
            _ = tokio::time::sleep_until(assign_deadline), if !ever_assigned => Event::AssignTimeout,
            _ = wait_shutdown(config.shutdown.as_ref()) => Event::Shutdown,
        };

        match event {
            Event::Capsule(Some(buf)) => {
                parser.push(&buf[..]);
                loop {
                    match parser.next_capsule() {
                        Ok(Some(capsule)) => {
                            handle_capsule(capsule, tun, config, routes, proxy_ip, dns)?
                        }
                        Ok(None) => break,
                        Err(e) => return Err(format!("malformed capsule: {e}").into()),
                    }
                }
                ever_assigned |= tun.is_some();
            }
            Event::Capsule(None) => return Err("session closed by proxy".into()),
            Event::CapsuleErr(e) => return Err(format!("capsule stream error: {e}").into()),
            Event::Datagram(Some(buf)) => {
                if let Some((_, 0, payload)) = decode_datagram_ctx(&buf) {
                    if let Some(b) = tun.as_ref() {
                        // try_send: drop instead of blocking if the TUN is full.
                        if b.dev.try_send(payload).is_ok() {
                            if let Some(s) = config.stats.as_ref() {
                                s.rx.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
            Event::Datagram(None) => return Err("datagram flow closed by proxy".into()),
            Event::Tun(Err(e)) => {
                // The device is likely gone; drop it so the next connection
                // creates a fresh one.
                *tun = None;
                return Err(format!("TUN recv error: {e}").into());
            }
            Event::Tun(Ok(n)) => {
                // Oversized for one datagram: reply ICMP Packet Too Big so the
                // local source lowers its MTU, instead of dropping it silently
                // (RFC 9484 §7.1).
                if n as u32 > TUNNEL_IP_MTU {
                    if let Some(icmp) = crate::icmp::packet_too_big(&pkt_buf[..n], TUNNEL_IP_MTU) {
                        if let Some(b) = tun.as_ref() {
                            let _ = b.dev.try_send(&icmp);
                        }
                    }
                    continue;
                }
                // RFC 9484 §7.1: decrement the hop count right before the packet
                // is transmitted in an HTTP Datagram. Drop it if exhausted.
                if !decrement_hop_limit(&mut pkt_buf[..n]) {
                    log::trace!("[client] dropping hop-limit-exhausted packet");
                    continue;
                }
                match dgram_conn.send_datagram(encode_datagram(quic_stream_id, &pkt_buf[..n])) {
                    Ok(()) => {
                        if let Some(s) = config.stats.as_ref() {
                            s.tx.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    Err(quinn::SendDatagramError::TooLarge) => {
                        log::trace!("[client] drop oversized datagram: {n} bytes")
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Event::TunFdChanged => {
                // Swap the forwarding device onto the replacement fd, keeping
                // the QUIC connection and the assigned address set. If no
                // device exists yet, the slot value is simply picked up by the
                // next create_device.
                if let (Some(slot), Some(binding)) = (config.tun_fd.as_ref(), tun.as_mut()) {
                    let fd = slot.current();
                    if fd >= 0 && binding.fd != Some(fd) {
                        match crate::tun_platform::adopt_device(fd) {
                            Ok(dev) => {
                                binding.dev = Arc::new(dev);
                                binding.fd = Some(fd);
                                log::info!("[client] adopted replacement TUN fd from host");
                            }
                            Err(e) => {
                                return Err(format!("adopting replacement TUN fd failed: {e}").into())
                            }
                        }
                    }
                }
            }
            Event::AssignTimeout => {
                return Err("proxy did not assign an address within 10s".into())
            }
            Event::Shutdown => {
                // Close the QUIC connection so the proxy sees an explicit
                // CONNECTION_CLOSE and releases our assigned address at once,
                // instead of holding it until its ~30s idle timeout. Drain the
                // endpoints briefly so the close frame is actually transmitted
                // before the runtime is torn down; bounded so stop never hangs.
                conn.close(0u32.into(), b"client stopping");
                let drain = async {
                    if let Some(ep) = &ep_v4 {
                        ep.wait_idle().await;
                    }
                    if let Some(ep) = &ep_v6 {
                        ep.wait_idle().await;
                    }
                };
                let _ = tokio::time::timeout(Duration::from_millis(500), drain).await;
                log::info!("[client] shutdown: closed connection, releasing address");
                return Ok(TunnelExit::Shutdown);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_capsule(
    capsule: Capsule,
    tun: &mut Option<TunBinding>,
    config: &IpClientConfig,
    routes: &mut crate::route::RouteSet,
    proxy_ip: IpAddr,
    dns: &mut crate::dns::DnsGuard,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match capsule.capsule_type {
        CAPSULE_ADDRESS_ASSIGN => {
            let Some(addrs) = parse_address_assign(&capsule.payload) else {
                return Err("malformed ADDRESS_ASSIGN".into());
            };
            // RFC 9484 §4.7.1 is declarative: this carries the complete current
            // address set (all-zero entries are refusals, not assignments; an
            // empty set withdraws all addresses). Reconcile the device to match.
            let mut new_addrs: Vec<(IpAddr, u8)> = addrs
                .iter()
                .filter(|a| !a.addr.is_unspecified())
                .map(|a| (a.addr, a.prefix_len))
                .collect();
            new_addrs.sort();
            new_addrs.dedup();
            apply_address_assign(tun, routes, &new_addrs, config)?;
            // iOS/tvOS: the host programs NEIPv4/6Settings from the assigned
            // set. On desktop `events` is None and the TUN already carries them.
            if let Some(events) = &config.events {
                events.addresses_assigned(&new_addrs);
            }
        }
        CAPSULE_ROUTE_ADVERTISEMENT => {
            let Some(ranges) = parse_route_advertisement(&capsule.payload) else {
                return Err("malformed ROUTE_ADVERTISEMENT".into());
            };
            // Routes point into the TUN, which the preceding ADDRESS_ASSIGN
            // creates; without it there is nothing to route toward.
            let Some(binding) = tun.as_ref() else {
                log::warn!("[client] ROUTE_ADVERTISEMENT before an address was assigned; ignoring");
                return Ok(());
            };
            for r in &ranges {
                let proto = if r.ip_proto == 0 {
                    "any".to_string()
                } else {
                    r.ip_proto.to_string()
                };
                log::info!(
                    "[client] Proxy advertises route: {} - {} proto={proto}",
                    r.start,
                    r.end
                );
            }
            // iOS/tvOS: the host programs routes + DNS (NEIPv4Route /
            // NEDNSSettings) from the advertisement; desktop installs them here.
            if let Some(events) = &config.events {
                events.routes_advertised(&ranges);
                return Ok(());
            }
            let tun_name = crate::tun_platform::device_name(&binding.dev);
            for r in &ranges {
                // Full tunnel is only taken over on opt-in (RFC 9484 §4.7.3
                // leaves this to local policy); hint if the operator hasn't.
                if crate::route::is_default_range(r.start, r.end) && !config.redirect_gateway {
                    log::info!(
                        "[client] full tunnel offered; pass --redirect-gateway to route all \
                         traffic through it (leaving the default route untouched)"
                    );
                }
            }
            // Declarative reconcile: install newly advertised ranges and
            // withdraw any that this advertisement no longer contains.
            if let Err(e) = routes.reconcile(&ranges, config.redirect_gateway, proxy_ip, &tun_name) {
                log::error!("[client] failed to apply advertised routes: {e}");
            }
            // Routes are now current; take over DNS if requested (idempotent).
            if dns.is_enabled() {
                if let Err(e) = dns.ensure_applied(routes) {
                    log::error!("[client] failed to set DNS: {e}");
                }
            }
        }
        CAPSULE_DNS_ASSIGN => {
            let Some(servers) = parse_dns_assign(&capsule.payload) else {
                log::warn!("[client] malformed DNS_ASSIGN");
                return Ok(());
            };
            log::info!("[client] DNS_ASSIGN received: {servers:?}");
            if servers.is_empty() {
                return Ok(());
            }
            // iOS/tvOS: the host programs NEDNSSettings. On desktop, adopt the
            // pushed resolvers unless the operator set --dns explicitly.
            if let Some(events) = &config.events {
                events.dns_assigned(&servers);
            } else {
                match dns.adopt_pushed(servers, routes) {
                    Ok(true) => {}
                    Ok(false) => {
                        log::info!("[client] DNS_ASSIGN ignored (--dns override in effect)")
                    }
                    Err(e) => log::error!("[client] failed to apply DNS_ASSIGN: {e}"),
                }
            }
        }
        CAPSULE_ADDRESS_REQUEST => {
            log::debug!("[client] Ignoring ADDRESS_REQUEST from proxy");
        }
        // Unknown capsule types must be ignored (RFC 9297 §3.2).
        other => log::trace!("[client] Ignoring unknown capsule type {other:#x}"),
    }
    Ok(())
}

/// Apply a declarative ADDRESS_ASSIGN (RFC 9484 §4.7.1): reconcile the TUN's
/// addresses with the complete set `new_addrs`. The device is created on the
/// first assignment, updated in place when the set changes (keeping its name
/// and any installed routes), and torn down when the set becomes empty.
fn apply_address_assign(
    tun: &mut Option<TunBinding>,
    routes: &mut crate::route::RouteSet,
    new_addrs: &[(IpAddr, u8)],
    config: &IpClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match tun.as_mut() {
        None => {
            if new_addrs.is_empty() {
                return Ok(()); // no device and no addresses — nothing to do
            }
            let host_fd = config.tun_fd.as_ref().map(|slot| slot.current());
            let dev = crate::tun_platform::create_device(
                new_addrs,
                config.mtu,
                config.tun_name.as_deref(),
                host_fd,
            )?;
            let name = crate::tun_platform::device_name(&dev);
            log::info!(
                "[client] TUN {name} up: {} mtu={}",
                fmt_addrs(new_addrs),
                config.mtu
            );
            *tun = Some(TunBinding {
                dev: Arc::new(dev),
                addrs: new_addrs.to_vec(),
                fd: host_fd,
            });
        }
        Some(binding) => {
            if binding.addrs.as_slice() == new_addrs {
                return Ok(()); // unchanged
            }
            // Empty set withdraws all addresses: tear the device (and the
            // routes that point at it) down.
            if new_addrs.is_empty() {
                routes.revert();
                *tun = None;
                log::info!("[client] all addresses withdrawn; TUN removed");
                return Ok(());
            }
            // Incremental diff: add new addresses, remove withdrawn ones,
            // keeping the device (its name and installed routes) intact.
            // Host-managed devices (adopted fd) are skipped: the host programs
            // addresses from the `addresses_assigned` callback, and tun-rs
            // ioctls on the adopted utun are denied in the NE sandbox anyway.
            if config.tun_fd.is_none() {
                let cur: std::collections::HashSet<(IpAddr, u8)> =
                    binding.addrs.iter().copied().collect();
                let want: std::collections::HashSet<(IpAddr, u8)> =
                    new_addrs.iter().copied().collect();
                for (addr, prefix) in new_addrs.iter().filter(|a| !cur.contains(a)) {
                    crate::tun_platform::add_address(&binding.dev, *addr, *prefix)?;
                }
                for (addr, _prefix) in binding.addrs.iter().filter(|a| !want.contains(a)) {
                    crate::tun_platform::remove_address(&binding.dev, *addr)?;
                }
            }
            binding.addrs = new_addrs.to_vec();
            log::info!("[client] address set updated: {}", fmt_addrs(new_addrs));
        }
    }
    Ok(())
}

/// Render an assignment set like `10.99.0.2/32, 2001:db8:1::2/128`.
fn fmt_addrs(addrs: &[(IpAddr, u8)]) -> String {
    addrs
        .iter()
        .map(|(a, p)| format!("{a}/{p}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn interleave_alternates_starting_with_system_preference() {
        let addrs = vec![
            sa("[2001:db8::1]:443"),
            sa("[2001:db8::2]:443"),
            sa("10.0.0.1:443"),
        ];
        assert_eq!(
            interleave_families(addrs),
            vec![
                sa("[2001:db8::1]:443"),
                sa("10.0.0.1:443"),
                sa("[2001:db8::2]:443"),
            ]
        );
    }

    #[test]
    fn interleave_v4_first_when_system_prefers_v4() {
        let addrs = vec![sa("10.0.0.1:443"), sa("[2001:db8::1]:443")];
        assert_eq!(
            interleave_families(addrs),
            vec![sa("10.0.0.1:443"), sa("[2001:db8::1]:443")]
        );
    }

    #[test]
    fn interleave_single_family_is_unchanged() {
        let addrs = vec![sa("10.0.0.1:443"), sa("10.0.0.2:443")];
        assert_eq!(interleave_families(addrs.clone()), addrs);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn request_prefers_held_over_configured() {
        // A held address (reconnect) must win, so the tunnel IP stays stable.
        assert_eq!(
            request_address(Some(ip("10.0.0.5")), Some(ip("10.0.0.9")), IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ip("10.0.0.5")
        );
    }

    #[test]
    fn request_uses_configured_when_nothing_held() {
        // Cold start: no held address, so the configured preference is requested.
        assert_eq!(
            request_address(None, Some(ip("10.0.0.9")), IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ip("10.0.0.9")
        );
    }

    #[test]
    fn request_ignores_preference_of_other_family() {
        // A preference only fills its own family's slot.
        assert_eq!(
            request_address(None, Some(ip("2001:db8::2")), IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(
            request_address(None, Some(ip("10.0.0.9")), IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn request_defaults_to_unspecified_without_preference() {
        // Empty config keeps the previous all-zero "no preference" request.
        assert_eq!(
            request_address(None, None, IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }
}
