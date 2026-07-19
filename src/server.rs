//! MASQUE proxy server on the quiche / tokio-quiche stack.
//!
//! Accepts HTTP/3 extended CONNECT requests. CONNECT-UDP (RFC 9298) is served
//! here; CONNECT-IP (RFC 9484) dispatch is added in `ip_server`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::UdpSocket;

use tokio_quiche::datagram_socket::DgramBuffer;
use tokio_quiche::http3::driver::{
    H3Event, IncomingH3Headers, InboundFrame, InboundFrameStream, OutboundFrame,
    OutboundFrameSender, ServerH3Event,
};
use tokio_quiche::http3::settings::Http3Settings;
use tokio_quiche::metrics::DefaultMetrics;
use tokio_quiche::quiche::h3::{Header, NameValue};
use tokio_quiche::settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths};
use tokio_quiche::{listen, ConnectionParams, ServerH3Controller, ServerH3Driver};

use crate::common::*;
use crate::ip_server::{self, IpTunState};

/// Server configuration parsed from CLI arguments.
pub struct ServerConfig {
    pub listen: String,
    pub cert: String,
    pub key: String,
    pub auth_token: Option<String>,
    /// When set, enables CONNECT-IP with this IPv4 pool (CIDR).
    pub ip_pool: Option<String>,
    /// When set, enables CONNECT-IP with this IPv6 pool (CIDR).
    pub ip6_pool: Option<String>,
    /// MTU of the CONNECT-IP TUN device.
    pub ip_mtu: u16,
    /// Optional name for the CONNECT-IP TUN device.
    pub ip_tun_name: Option<String>,
}

/// Transport tuning shared by all proxied protocols.
pub(crate) fn server_quic_settings() -> QuicSettings {
    let mut qs = QuicSettings::default();
    qs.cc_algorithm = "bbr2".to_string();
    qs.enable_dgram = true;
    qs.dgram_recv_max_queue_len = 65_536;
    qs.dgram_send_max_queue_len = 65_536;
    qs.max_idle_timeout = Some(Duration::from_secs(30));
    qs
}

/// Run the MASQUE proxy server.
pub async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let socket = UdpSocket::bind(listen_addr).await?;

    let params = ConnectionParams::new_server(
        server_quic_settings(),
        TlsCertificatePaths {
            cert: config.cert.as_str(),
            private_key: config.key.as_str(),
            kind: CertificateKind::X509,
        },
        Hooks::default(),
    );

    let mut listeners = listen([socket], params, DefaultMetrics)?;
    log::info!("[server] MASQUE server listening on {listen_addr}");

    // CONNECT-IP is opt-in: it needs a TUN device (root) and an address pool.
    let ip_state = if config.ip_pool.is_some() || config.ip6_pool.is_some() {
        Some(ip_server::init(&ip_server::IpConfig {
            pool_v4: config.ip_pool.clone(),
            pool_v6: config.ip6_pool.clone(),
            mtu: config.ip_mtu,
            tun_name: config.ip_tun_name.clone(),
        })?)
    } else {
        None
    };

    let auth = Arc::new(config.auth_token.clone());
    let accept = &mut listeners[0];
    while let Some(conn) = accept.next().await {
        let conn = match conn {
            Ok(c) => c,
            Err(e) => {
                log::error!("[server] accept error: {e:?}");
                continue;
            }
        };
        log::info!("[server] new connection");

        let (driver, controller) = ServerH3Driver::new(Http3Settings {
            enable_extended_connect: true,
            ..Default::default()
        });
        conn.start(driver);

        let auth = auth.clone();
        let ip_state = ip_state.clone();
        tokio::spawn(async move {
            handle_connection(controller, auth, ip_state).await;
            log::info!("[server] connection closed");
        });
    }

    Ok(())
}

async fn handle_connection(
    mut controller: ServerH3Controller,
    auth: Arc<Option<String>>,
    ip_state: Option<Arc<IpTunState>>,
) {
    // NewFlow fires before Headers for a CONNECT request; stash flow halves by
    // flow_id and pair them on Headers (flow_id == stream_id / 4).
    let mut pending_flows: HashMap<u64, (OutboundFrameSender, InboundFrameStream)> = HashMap::new();

    while let Some(ev) = controller.event_receiver_mut().recv().await {
        match ev {
            ServerH3Event::Core(H3Event::NewFlow {
                flow_id,
                send,
                recv,
            }) => {
                pending_flows.insert(flow_id, (send, recv));
            }
            ServerH3Event::Headers {
                incoming_headers, ..
            } => {
                handle_request(incoming_headers, &mut pending_flows, &auth, &ip_state).await;
            }
            ServerH3Event::Core(H3Event::ConnectionShutdown(_))
            | ServerH3Event::Core(H3Event::ConnectionError(_)) => break,
            _ => {}
        }
    }
}

/// Send a bare status response (no body, no FIN) on a request stream.
async fn reply_status(send: &mut OutboundFrameSender, status: &[u8]) {
    let _ = send
        .send(OutboundFrame::Headers(
            vec![Header::new(b":status", status)],
            None,
        ))
        .await;
}

async fn handle_request(
    headers: IncomingH3Headers,
    pending_flows: &mut HashMap<u64, (OutboundFrameSender, InboundFrameStream)>,
    auth: &Arc<Option<String>>,
    ip_state: &Option<Arc<IpTunState>>,
) {
    let IncomingH3Headers {
        stream_id,
        headers: hdrs,
        mut send,
        recv,
        ..
    } = headers;

    let (mut method, mut protocol, mut path, mut authz) = (None, None, None, None);
    for h in &hdrs {
        match h.name() {
            b":method" => method = Some(h.value().to_vec()),
            b":protocol" => protocol = Some(h.value().to_vec()),
            b":path" => path = Some(h.value().to_vec()),
            b"proxy-authorization" => authz = Some(h.value().to_vec()),
            _ => {}
        }
    }

    // Auth check.
    if let Some(expected) = auth.as_ref() {
        let expected_header = format!("Bearer {expected}");
        if authz.as_deref() != Some(expected_header.as_bytes()) {
            log::warn!("[server] auth failed");
            reply_status(&mut send, b"407").await;
            return;
        }
    }

    let is_connect = method.as_deref() == Some(b"CONNECT");
    match protocol.as_deref() {
        Some(b"connect-udp") if is_connect => {}
        Some(b"connect-ip") if is_connect => {
            let Some(ip_state) = ip_state else {
                log::info!("[server] CONNECT-IP request but no --ip-pool configured");
                reply_status(&mut send, b"501").await;
                return;
            };
            let flow_id = stream_id / 4;
            let Some((flow_send, flow_recv)) = pending_flows.remove(&flow_id) else {
                log::warn!("[server] no datagram flow for CONNECT-IP stream_id={stream_id}");
                return;
            };
            let path_str = path
                .as_deref()
                .and_then(|p| std::str::from_utf8(p).ok())
                .unwrap_or("")
                .to_string();
            ip_server::handle_ip_request(
                ip_state, stream_id, &path_str, send, recv, flow_send, flow_recv,
            )
            .await;
            return;
        }
        _ => {
            reply_status(&mut send, b"405").await;
            return;
        }
    }

    // Parse target host/port from the path.
    let target = path
        .as_deref()
        .and_then(|p| std::str::from_utf8(p).ok())
        .and_then(parse_connect_udp_path);
    let Some((host, port)) = target else {
        log::info!("[server] invalid CONNECT-UDP path");
        reply_status(&mut send, b"400").await;
        return;
    };

    // Resolve and connect to the target.
    let target_addr = match resolve_target(&host, port).await {
        Some(a) => a,
        None => {
            reply_status(&mut send, b"502").await;
            return;
        }
    };
    let bind = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let udp = match UdpSocket::bind(bind).await {
        Ok(u) => u,
        Err(e) => {
            log::error!("[server] cannot bind target socket: {e}");
            reply_status(&mut send, b"502").await;
            return;
        }
    };
    if let Err(e) = udp.connect(target_addr).await {
        log::error!("[server] cannot connect to {target_addr}: {e}");
        reply_status(&mut send, b"502").await;
        return;
    }

    let flow_id = stream_id / 4;
    let Some((flow_send, flow_recv)) = pending_flows.remove(&flow_id) else {
        log::warn!("[server] no datagram flow for stream_id={stream_id}");
        return;
    };

    reply_status(&mut send, b"200").await;
    log::info!("[server] CONNECT-UDP established: stream_id={stream_id} target={target_addr}");

    tokio::spawn(bridge_target(
        flow_id,
        flow_send,
        flow_recv,
        Arc::new(udp),
        send,
    ));
}

/// Bridge a connected target UDP socket to the tunnel's datagram flow.
async fn bridge_target(
    flow_id: u64,
    mut flow_send: OutboundFrameSender,
    mut flow_recv: InboundFrameStream,
    udp: Arc<UdpSocket>,
    _stream_keepalive: OutboundFrameSender,
) {
    // tunnel -> target
    let udp_tx = udp.clone();
    let t1 = tokio::spawn(async move {
        while let Some(frame) = flow_recv.recv().await {
            let InboundFrame::Datagram(buf) = frame else {
                continue;
            };
            if let Some((0, payload)) = decode_context_payload(buf.as_slice()) {
                let _ = udp_tx.send(payload).await;
            }
        }
    });

    // target -> tunnel
    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = udp.recv(&mut buf).await {
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

    let _ = tokio::join!(t1, t2);
}

async fn resolve_target(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .ok()?
        .next()
}
