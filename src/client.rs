//! CONNECT-UDP client (RFC 9298) on the quiche / tokio-quiche stack.
//!
//! Binds a local UDP socket and tunnels its traffic to the proxy over an
//! HTTP/3 extended CONNECT with `:protocol = connect-udp`. The proxy path
//! carries the target host/port; datagrams flow on the request's DATAGRAM
//! flow with an RFC 9298 context ID of 0.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};

use tokio_quiche::datagram_socket::DgramBuffer;
use tokio_quiche::http3::driver::{
    ClientH3Event, H3Event, InboundFrame, InboundFrameStream, NewClientRequest, OutboundFrame,
    OutboundFrameSender,
};
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::quic::ConnectionHook;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{
    CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths,
};
use tokio_quiche::ClientH3Driver;

use crate::common::*;

/// Client configuration parsed from CLI arguments.
pub struct ClientConfig {
    pub listen: String,
    pub proxy_url: String,
    pub target: String,
    pub sni: Option<String>,
    pub auth_token: Option<String>,
    pub insecure: bool,
    pub ca: Option<String>,
}

/// Transport tuning shared by the CONNECT-UDP and CONNECT-IP clients.
pub(crate) fn client_quic_settings(insecure: bool) -> QuicSettings {
    let mut qs = QuicSettings::default();
    qs.cc_algorithm = "bbr2".to_string();
    qs.enable_dgram = true;
    qs.dgram_recv_max_queue_len = 65_536;
    qs.dgram_send_max_queue_len = 65_536;
    // See server.rs for the three DATAGRAM size caps. The dominant one is
    // max_recv_udp_payload_size: it is advertised to the peer, and quiche's
    // send path caps on the peer's value, so tokio-quiche's 1350 default makes
    // the *server* drop our large upstream datagrams regardless of the send
    // ceiling or PMTUD. Raise all three so full-size WireGuard packets fit.
    qs.max_recv_udp_payload_size = 1452;
    qs.max_send_udp_payload_size = 1452;
    qs.discover_path_mtu = true;
    // See server.rs: quiche's h3 GREASE frames on the response stream break
    // Apple's NWConnection relay. Disable grease on the client too for symmetry
    // and so we never emit reserved frames ahead of HEADERS to a strict peer.
    qs.grease = false;
    qs.max_idle_timeout = Some(Duration::from_secs(30));
    // verify_peer defaults to false in tokio-quiche; only enable it when the
    // caller did not ask for --insecure. Custom-CA (--ca) support still needs
    // a BoringSSL ConnectionHook and is handled by the caller.
    qs.verify_peer = !insecure;
    qs
}

/// A BoringSSL ConnectionHook that trusts a custom CA PEM (for `--ca`).
struct CaHook {
    ca_path: String,
}

impl ConnectionHook for CaHook {
    fn create_custom_ssl_context_builder(
        &self,
        _settings: TlsCertificatePaths<'_>,
    ) -> Option<SslContextBuilder> {
        let mut b = SslContextBuilder::new(SslMethod::tls_client()).ok()?;
        if let Err(e) = b.set_ca_file(&self.ca_path) {
            log::error!("[client] failed to load --ca {}: {e}", self.ca_path);
            return None;
        }
        b.set_verify(SslVerifyMode::PEER);
        Some(b)
    }
}

/// Build client connection params. With `--ca` a BoringSSL hook loads the
/// custom CA and verifies the peer against it; with `--insecure` verification
/// is off; otherwise the system trust store is used.
pub(crate) fn build_client_params(insecure: bool, ca: &Option<String>) -> ConnectionParams<'_> {
    let qs = client_quic_settings(insecure);
    match ca {
        Some(ca_path) if !insecure => {
            let hooks = Hooks {
                connection_hook: Some(std::sync::Arc::new(CaHook {
                    ca_path: ca_path.clone(),
                })),
            };
            // tls_cert must be Some to trigger the hook; the hook loads the CA
            // itself and ignores these paths, so they are just placeholders.
            let tls = TlsCertificatePaths {
                cert: ca_path,
                private_key: ca_path,
                kind: CertificateKind::X509,
            };
            ConnectionParams::new_client(qs, Some(tls), hooks)
        }
        _ => ConnectionParams::new_client(qs, None, Hooks::default()),
    }
}

/// Run the MASQUE CONNECT-UDP client with automatic reconnection.
pub async fn run(config: ClientConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let url = url::Url::parse(&config.proxy_url)?;
    let proxy_host = url.host_str().ok_or("missing host in proxy URL")?.to_string();
    let proxy_port = url.port().unwrap_or(443);
    let sni = config.sni.clone().unwrap_or_else(|| proxy_host.clone());
    let (target_host, target_port) = parse_target(&config.target)?;

    let proxy_addr = tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}"))
        .await?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {proxy_host}:{proxy_port}"))?;

    let local = Arc::new(UdpSocket::bind(listen_addr).await?);
    log::info!(
        "[client] Listening on {listen_addr}, proxy={proxy_host}:{proxy_port}, target={target_host}:{target_port}"
    );

    let mut backoff_ms = 500u64;
    loop {
        let outcome = run_tunnel(
            &config,
            &proxy_host,
            &sni,
            proxy_addr,
            &local,
            &target_host,
            target_port,
        )
        .await;
        match outcome {
            Ok(()) => log::warn!("[client] tunnel ended, reconnecting in {backoff_ms}ms"),
            Err(e) => log::warn!("[client] connection lost: {e}, reconnecting in {backoff_ms}ms"),
        }
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(30_000);
    }
}

async fn run_tunnel(
    config: &ClientConfig,
    proxy_host: &str,
    sni: &str,
    proxy_addr: SocketAddr,
    local: &Arc<UdpSocket>,
    target_host: &str,
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind = if proxy_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let qsock = UdpSocket::bind(bind).await?;
    qsock.connect(proxy_addr).await?;

    let params = build_client_params(config.insecure, &config.ca);
    let (driver, mut controller) = ClientH3Driver::new(Http3Settings::default());
    let socket: tokio_quiche::socket::Socket<_, _> = qsock.try_into()?;
    let _conn = tokio_quiche::quic::connect_with_config(socket, Some(sni), &params, driver).await?;
    log::info!("[client] QUIC connected to {proxy_addr}");

    // Build the CONNECT-UDP request (RFC 9298). The target host is
    // percent-encoded so IPv6 literals form a valid path segment.
    let encoded_host = encode_target_host(target_host);
    let path = format!("{CONNECT_UDP_PATH}/{encoded_host}/{target_port}/");
    let mut headers = vec![
        Header::new(b":method", b"CONNECT"),
        Header::new(b":protocol", b"connect-udp"),
        Header::new(b":scheme", b"https"),
        Header::new(b":authority", proxy_host.as_bytes()),
        Header::new(b":path", path.as_bytes()),
    ];
    let auth_value;
    if let Some(token) = &config.auth_token {
        auth_value = format!("Bearer {token}");
        headers.push(Header::new(b"proxy-authorization", auth_value.as_bytes()));
    }

    // body_writer = Some sends the request without FIN so the stream (and its
    // datagram flow) stays open for the tunnel's lifetime.
    let (body_tx, body_rx) = oneshot::channel::<OutboundFrameSender>();
    controller
        .request_sender()
        .send(NewClientRequest {
            request_id: 1,
            headers,
            body_writer: Some(body_tx),
        })
        .map_err(|_| "failed to queue CONNECT-UDP request")?;

    // Collect the datagram flow (NewFlow) and the 200 response before bridging.
    let mut flow: Option<(OutboundFrameSender, InboundFrameStream, u64)> = None;
    let mut status_ok = false;
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
                status_ok = status.as_deref() == Some(b"200");
                if !status_ok {
                    return Err(format!(
                        "CONNECT-UDP rejected: :status={}",
                        status
                            .map(|s| String::from_utf8_lossy(&s).into_owned())
                            .unwrap_or_else(|| "(none)".into())
                    )
                    .into());
                }
            }
            ClientH3Event::Core(H3Event::ConnectionError(e)) => {
                return Err(format!("connection error: {e}").into())
            }
            ClientH3Event::Core(H3Event::ConnectionShutdown(_)) => {
                return Err("connection shut down before tunnel came up".into())
            }
            _ => {}
        }
        if flow.is_some() && status_ok {
            break;
        }
    }

    let (flow_send, flow_recv, flow_id) =
        flow.ok_or("proxy never opened a datagram flow")?;
    log::info!(
        "[client] CONNECT-UDP established (flow_id={flow_id}) target={target_host}:{target_port}"
    );

    // Park the request-stream sender so the driver never tears the stream down.
    let _keepalive = body_rx.await.ok();

    bridge_local_udp(local.clone(), flow_send, flow_recv, flow_id).await;
    drop(controller);
    Ok(())
}

/// Bridge the local UDP socket to the tunnel's datagram flow. Tracks the most
/// recent local peer so replies from the tunnel go back to the right sender.
async fn bridge_local_udp(
    local: Arc<UdpSocket>,
    mut flow_send: OutboundFrameSender,
    mut flow_recv: InboundFrameStream,
    flow_id: u64,
) {
    let peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    let local_rx = local.clone();
    let peer_w = peer.clone();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, src)) = local_rx.recv_from(&mut buf).await {
            *peer_w.lock().await = Some(src);
            let body = encode_context_payload(0, &buf[..n]);
            if flow_send
                .send(OutboundFrame::Datagram(DgramBuffer::from_slice(&body), flow_id))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let down = tokio::spawn(async move {
        while let Some(frame) = flow_recv.recv().await {
            let InboundFrame::Datagram(buf) = frame else {
                continue;
            };
            if let Some((0, payload)) = decode_context_payload(buf.as_slice()) {
                if let Some(dst) = *peer.lock().await {
                    let _ = local.send_to(payload, dst).await;
                }
            }
        }
    });

    let _ = tokio::join!(up, down);
}

fn parse_target(addr: &str) -> Result<(String, u16), String> {
    if let Some(bracket_end) = addr.rfind(']') {
        let host = &addr[..=bracket_end];
        let port_str = addr[bracket_end + 1..].trim_start_matches(':');
        let port: u16 = port_str.parse().map_err(|e| format!("Invalid port: {e}"))?;
        Ok((host.to_string(), port))
    } else {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() != 2 {
            return Err("Invalid address format, expected host:port".to_string());
        }
        let port: u16 = parts[0].parse().map_err(|e| format!("Invalid port: {e}"))?;
        Ok((parts[1].to_string(), port))
    }
}
