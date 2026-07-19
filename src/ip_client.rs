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

    let mut backoff_ms = 500u64;
    loop {
        match run_tunnel(&config, &proxy_host, &sni, proxy_addr, &mut tun).await {
            Ok(()) => log::warn!("[client] tunnel ended, reconnecting in {backoff_ms}ms"),
            Err(e) => log::warn!("[client] connection lost: {e}, reconnecting in {backoff_ms}ms"),
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(30_000);
    }
}

/// One event handled by the forwarding loop, collected as an owned value so
/// the borrows taken inside `select!` end before we touch `tun`.
enum Event {
    Capsule(Option<InboundFrame>),
    Datagram(Option<InboundFrame>),
    Tun(std::io::Result<usize>),
}

async fn run_tunnel(
    config: &IpClientConfig,
    proxy_host: &str,
    sni: &str,
    proxy_addr: std::net::SocketAddr,
    tun: &mut Option<TunBinding>,
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
    // The proxy must assign an address promptly; reconnect if none arrives.
    let assign_deadline = tokio::time::Instant::now() + Duration::from_secs(10);

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
            _ = tokio::time::sleep_until(assign_deadline), if tun.is_none() => {
                return Err("proxy did not assign an address within 10s".into());
            }
        };

        match event {
            Event::Capsule(Some(InboundFrame::Body(buf, _fin))) => {
                parser.push(&buf[..]);
                loop {
                    match parser.next_capsule() {
                        Ok(Some(capsule)) => handle_capsule(capsule, tun, config)?,
                        Ok(None) => break,
                        Err(e) => return Err(format!("malformed capsule: {e}").into()),
                    }
                }
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

fn handle_capsule(
    capsule: Capsule,
    tun: &mut Option<TunBinding>,
    config: &IpClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match capsule.capsule_type {
        CAPSULE_ADDRESS_ASSIGN => {
            let Some(addrs) = parse_address_assign(&capsule.payload) else {
                return Err("malformed ADDRESS_ASSIGN".into());
            };
            // Collect every usable assignment (all-zero entries are refusals of
            // hypothetical requests, not assignments). Sort so the set can be
            // compared cheaply against the current binding across reconnects.
            let mut new_addrs: Vec<(IpAddr, u8)> = addrs
                .iter()
                .filter(|a| !a.addr.is_unspecified())
                .map(|a| (a.addr, a.prefix_len))
                .collect();
            new_addrs.sort();
            new_addrs.dedup();
            if new_addrs.is_empty() {
                return Err("proxy assigned no usable address".into());
            }
            if tun.as_ref().is_some_and(|b| b.addrs == new_addrs) {
                log::info!(
                    "[client] Address assignment unchanged ({}), reusing TUN",
                    fmt_addrs(&new_addrs)
                );
                return Ok(());
            }
            let dev = create_tun(&new_addrs, config)?;
            let name = dev.name().unwrap_or_else(|_| "?".into());
            log::info!(
                "[client] TUN {name} up: {} mtu={}. Route traffic into it, e.g. \
                 `sudo route add -net 192.0.2.0/24 -interface {name}` (macOS) or \
                 `sudo ip route add 192.0.2.0/24 dev {name}` (Linux)",
                fmt_addrs(&new_addrs),
                config.mtu
            );
            *tun = Some(TunBinding {
                dev: Arc::new(dev),
                addrs: new_addrs,
            });
        }
        CAPSULE_ROUTE_ADVERTISEMENT => {
            let Some(ranges) = parse_route_advertisement(&capsule.payload) else {
                return Err("malformed ROUTE_ADVERTISEMENT".into());
            };
            for r in &ranges {
                log::info!(
                    "[client] Proxy advertises route: {} - {} proto={}",
                    r.start,
                    r.end,
                    if r.ip_proto == 0 {
                        "any".into()
                    } else {
                        r.ip_proto.to_string()
                    }
                );
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

fn create_tun(
    addrs: &[(IpAddr, u8)],
    config: &IpClientConfig,
) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = tun_rs::DeviceBuilder::new().mtu(config.mtu);
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
