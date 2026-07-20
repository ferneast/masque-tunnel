//! CONNECT-IP client (RFC 9484) on the quiche / tokio-quiche stack.
//!
//! Tunnels IP packets between a local TUN device and a MASQUE proxy. The TUN
//! device is created only after the proxy sends ADDRESS_ASSIGN, so the
//! interface always carries the proxy-assigned address(es). Across reconnects
//! the device is kept if the assignment is unchanged, preserving any routes
//! the operator added on top of it. Capsules arrive on the response stream
//! body; IP packets travel on the datagram flow with a context ID of 0.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::sync::oneshot;
use tun_rs::AsyncDevice;

use tokio_quiche::datagram_socket::DgramBuffer;
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, InboundFrameStream, NewClientRequest, OutboundFrame,
    OutboundFrameSender,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::ClientH3Driver;

use crate::capsule::*;
use crate::client::build_client_params;
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
}

/// The active TUN device plus the assignment it was configured with.
/// `addrs` holds the assigned addresses (IPv4 and/or IPv6), each with its
/// prefix length, sorted so reconnects can compare assignment sets cheaply.
struct TunBinding {
    dev: Arc<AsyncDevice>,
    addrs: Vec<(IpAddr, u8)>,
}

/// Run the MASQUE CONNECT-IP client with automatic reconnection.
pub async fn run(config: IpClientConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = url::Url::parse(&config.proxy_url)?;
    let proxy_host = url.host_str().ok_or("missing host in proxy URL")?.to_string();
    let proxy_port = url.port().unwrap_or(443);
    let sni = config.sni.clone().unwrap_or_else(|| proxy_host.clone());

    let proxy_addr = tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}"))
        .await?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {proxy_host}:{proxy_port}"))?;

    log::info!(
        "[client] CONNECT-IP mode, proxy={proxy_host}:{proxy_port} mtu={}",
        config.mtu
    );
    // Kept across reconnects so an unchanged assignment reuses the device
    // (and the operator's routes on it).
    let mut tun: Option<TunBinding> = None;
    // Host routes we install (full-tunnel redirect and/or specific routes),
    // reverted when this set drops — on shutdown signal below or process exit.
    let mut routes = crate::route::RouteSet::new();
    let mut dns = crate::dns::DnsGuard::new(config.dns.clone());
    let proxy_ip = proxy_addr.ip();

    let reconnect = async {
        let mut backoff_ms = 500u64;
        loop {
            match run_tunnel(
                &config, &proxy_host, &sni, proxy_addr, proxy_ip, &mut tun, &mut routes, &mut dns,
            )
            .await
            {
                Ok(()) => log::warn!("[client] tunnel ended, reconnecting in {backoff_ms}ms"),
                Err(e) => log::warn!("[client] connection lost: {e}, reconnecting in {backoff_ms}ms"),
            }
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
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

/// One event handled by the forwarding loop, collected as an owned value so
/// the borrows taken inside `select!` end before we touch `tun`.
enum Event {
    Capsule(Option<InboundFrame>),
    Datagram(Option<InboundFrame>),
    Tun(std::io::Result<usize>),
    Keepalive,
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    config: &IpClientConfig,
    proxy_host: &str,
    sni: &str,
    proxy_addr: std::net::SocketAddr,
    proxy_ip: IpAddr,
    tun: &mut Option<TunBinding>,
    routes: &mut crate::route::RouteSet,
    dns: &mut crate::dns::DnsGuard,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind = if proxy_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let qsock = tokio::net::UdpSocket::bind(bind).await?;
    qsock.connect(proxy_addr).await?;

    let params = build_client_params(config.insecure, &config.ca);
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let socket: tokio_quiche::socket::Socket<_, _> = qsock.try_into()?;
    let _conn = tokio_quiche::quic::connect_with_config(socket, Some(sni), &params, driver).await?;
    log::info!("[client] QUIC connected to {proxy_addr}");

    // Full-tunnel CONNECT-IP request: target and ipproto are both `*`.
    let path = format!("{CONNECT_IP_PATH}/*/*/");
    let mut headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-ip"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", proxy_host.as_bytes()),
        Header::new(b":path", path.as_bytes()),
    ];
    let auth_value;
    if let Some(token) = &config.auth_token {
        auth_value = format!("Bearer {token}");
        headers.push(Header::new(b"proxy-authorization", auth_value.as_bytes()));
    }

    let (body_tx, body_rx) = oneshot::channel::<OutboundFrameSender>();
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 1,
            headers,
            body_writer: Some(body_tx),
        })
        .map_err(|_| "failed to queue CONNECT-IP request")?;

    // Collect the datagram flow and the 200 response (which carries the
    // capsule body stream) before forwarding.
    let mut flow: Option<(OutboundFrameSender, InboundFrameStream, u64)> = None;
    let mut capsule_recv: Option<InboundFrameStream> = None;
    while let Some(ev) = controller.event_receiver_mut().recv().await {
        match ev {
            ClientH3Event::Core(H3Event::NewFlow {
                flow_id,
                send,
                recv,
            }) => flow = Some((send, recv, flow_id)),
            ClientH3Event::Core(H3Event::IncomingHeaders(h)) => {
                let status = h
                    .headers
                    .iter()
                    .find(|x| x.name() == b":status")
                    .map(|x| x.value().to_vec());
                if status.as_deref() != Some(b"200") {
                    return Err(format!(
                        "CONNECT-IP rejected: :status={}",
                        status
                            .map(|s| String::from_utf8_lossy(&s).into_owned())
                            .unwrap_or_else(|| "(none)".into())
                    )
                    .into());
                }
                capsule_recv = Some(h.recv);
            }
            ClientH3Event::Core(H3Event::ConnectionError(e)) => {
                return Err(format!("connection error: {e}").into())
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(_)) => {
                return Err("connection shut down before tunnel came up".into())
            }
            _ => {}
        }
        if flow.is_some() && capsule_recv.is_some() {
            break;
        }
    }

    let (mut flow_send, mut flow_recv, flow_id) =
        flow.ok_or("proxy never opened a datagram flow")?;
    let mut capsule_recv = capsule_recv.ok_or("proxy never sent a 200 response")?;
    log::info!("[client] CONNECT-IP established (flow_id={flow_id})");

    // Park the request-stream sender so the driver never tears the stream down.
    let _keepalive = body_rx.await.ok();

    let mut parser = CapsuleParser::default();
    let mut pkt_buf = vec![0u8; config.mtu.max(1280) as usize + 64];
    // The proxy must assign an address promptly on a fresh tunnel; reconnect if
    // none arrives. Once any address has been assigned, an empty ADDRESS_ASSIGN
    // (withdraw-all, RFC 9484 §4.7.1) is legal and must not trip the deadline.
    let mut ever_assigned = tun.is_some();
    let assign_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    // Keep an idle tunnel alive well under the 30s max_idle_timeout — otherwise
    // an idle CONNECT-IP session is torn down and reconnects every 30 seconds.
    let mut keepalive = tokio::time::interval(Duration::from_secs(10));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let event = tokio::select! {
            f = capsule_recv.recv() => Event::Capsule(f),
            f = flow_recv.recv() => Event::Datagram(f),
            r = async {
                match tun.as_ref() {
                    Some(b) => b.dev.recv(&mut pkt_buf).await,
                    None => std::future::pending().await,
                }
            } => Event::Tun(r),
            _ = keepalive.tick() => Event::Keepalive,
            _ = tokio::time::sleep_until(assign_deadline), if !ever_assigned => {
                return Err("proxy did not assign an address within 10s".into());
            }
        };

        match event {
            Event::Capsule(Some(InboundFrame::Body(buf, _fin))) => {
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
            Event::Capsule(Some(_)) => {}
            Event::Datagram(Some(InboundFrame::Datagram(buf))) => {
                if let Some((0, pkt)) = decode_context_payload(buf.as_slice()) {
                    if let Some(b) = tun.as_ref() {
                        // try_send: drop instead of blocking if the TUN is full.
                        let _ = b.dev.try_send(pkt);
                    }
                }
            }
            Event::Datagram(None) => return Err("datagram flow closed by proxy".into()),
            Event::Datagram(Some(_)) => {}
            Event::Keepalive => {
                // Empty ack-eliciting datagram keeps the QUIC connection under
                // max_idle_timeout while the tunnel is idle. context != 0, so
                // the proxy drops it instead of treating it as an IP packet.
                let _ = flow_send
                    .send(OutboundFrame::Datagram(
                        DgramBuffer::from_slice(&encode_context_payload(1, &[])),
                        flow_id,
                    ))
                    .await;
            }
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
                let body = encode_context_payload(0, &pkt_buf[..n]);
                if flow_send
                    .send(OutboundFrame::Datagram(DgramBuffer::from_slice(&body), flow_id))
                    .await
                    .is_err()
                {
                    return Err("datagram flow send failed".into());
                }
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
            let tun_name = binding.dev.name().unwrap_or_default();
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
            // Routes are now current; take over DNS if requested (idempotent,
            // so this only acts on the first advertisement).
            if dns.is_enabled() {
                if let Err(e) = dns.ensure_applied(routes) {
                    log::error!("[client] failed to set DNS: {e}");
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
            let dev = create_tun(new_addrs, config)?;
            let name = dev.name().unwrap_or_else(|_| "?".into());
            log::info!(
                "[client] TUN {name} up: {} mtu={}",
                fmt_addrs(new_addrs),
                config.mtu
            );
            *tun = Some(TunBinding {
                dev: Arc::new(dev),
                addrs: new_addrs.to_vec(),
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
            let cur: std::collections::HashSet<(IpAddr, u8)> =
                binding.addrs.iter().copied().collect();
            let want: std::collections::HashSet<(IpAddr, u8)> =
                new_addrs.iter().copied().collect();
            for (addr, prefix) in new_addrs.iter().filter(|a| !cur.contains(a)) {
                match addr {
                    IpAddr::V4(v4) => binding.dev.add_address_v4(*v4, *prefix)?,
                    IpAddr::V6(v6) => binding.dev.add_address_v6(*v6, *prefix)?,
                }
            }
            for (addr, _prefix) in binding.addrs.iter().filter(|a| !want.contains(a)) {
                binding.dev.remove_address(*addr)?;
            }
            binding.addrs = new_addrs.to_vec();
            log::info!("[client] address set updated: {}", fmt_addrs(new_addrs));
        }
    }
    Ok(())
}

fn create_tun(
    addrs: &[(IpAddr, u8)],
    config: &IpClientConfig,
) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = tun_rs::DeviceBuilder::new().mtu(config.mtu);
    // On macOS/BSD, tun-rs installs a host route for the assigned /32 (or /128)
    // whose gateway is the address itself; macOS rejects it with EADDRNOTAVAIL,
    // logging a noisy but harmless warning. We never want that route — traffic
    // is steered into the tunnel by routes the operator adds explicitly. Linux
    // has no such auto-route behavior (and `associate_route` is not defined
    // there), so this switch is macOS/BSD-only.
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        builder = builder.associate_route(false);
    }
    for (addr, prefix_len) in addrs {
        builder = match addr {
            IpAddr::V4(v4) => builder.ipv4(*v4, *prefix_len, None),
            IpAddr::V6(v6) => builder.ipv6(*v6, *prefix_len),
        };
    }
    if let Some(name) = &config.tun_name {
        builder = builder.name(name);
    }
    Ok(builder.build_async()?)
}

/// Render an assignment set like `10.99.0.2/32, 2001:db8:1::2/128`.
fn fmt_addrs(addrs: &[(IpAddr, u8)]) -> String {
    addrs
        .iter()
        .map(|(a, p)| format!("{a}/{p}"))
        .collect::<Vec<_>>()
        .join(", ")
}
