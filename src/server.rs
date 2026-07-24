use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use h3::ext::Protocol;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::common::*;
use crate::ip_server::{self, IpSession, IpTunState};

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
    /// Optional file of routes to advertise to CONNECT-IP clients (one CIDR
    /// per line). None/absent advertises a full tunnel.
    pub ip_routes_file: Option<String>,
    /// DNS resolver(s) to advertise to CONNECT-IP clients via a DNS_ASSIGN
    /// capsule (draft-ietf-masque-connect-ip-dns). Empty = no DNS_ASSIGN.
    pub dns_assign: Vec<std::net::IpAddr>,
}

/// Run the MASQUE CONNECT-UDP proxy server.
pub async fn run(config: ServerConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = config.listen.parse()?;

    let certs = load_certs(&config.cert)?;
    let key = load_key(&config.key)?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    server_crypto.max_early_data_size = u32::MAX;
    server_crypto.send_half_rtt_data = true;

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1350);
    transport.datagram_receive_buffer_size(Some(8_000_000));
    transport.datagram_send_buffer_size(8_000_000);
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(30)
            .try_into()
            .map_err(|e| format!("{e}"))?,
    ));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    log::info!("[server] MASQUE server listening on {listen_addr}");

    // CONNECT-IP is opt-in: it needs a TUN device (root) and an address pool.
    let ip_state = if config.ip_pool.is_some() || config.ip6_pool.is_some() {
        let advertised_routes = match &config.ip_routes_file {
            Some(path) => ip_server::parse_routes_file(path)?,
            None => Vec::new(),
        };
        Some(ip_server::init(&ip_server::IpConfig {
            pool_v4: config.ip_pool.clone(),
            pool_v6: config.ip6_pool.clone(),
            mtu: config.ip_mtu,
            tun_name: config.ip_tun_name.clone(),
            advertised_routes,
            advertised_dns: config.dns_assign.clone(),
        })?)
    } else {
        None
    };

    let auth_token = config.auth_token;
    while let Some(incoming) = endpoint.accept().await {
        let auth_token = auth_token.clone();
        let ip_state = ip_state.clone();
        tokio::spawn(async move {
            let conn = match incoming.accept() {
                Ok(c) => match c.await {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("[server] Connection failed: {e}");
                        return;
                    }
                },
                Err(e) => {
                    log::error!("[server] Accept error: {e}");
                    return;
                }
            };
            log::info!("[server] Connection from {}", conn.remote_address());
            if let Err(e) = handle_connection(conn, auth_token, ip_state).await {
                log::error!("[server] Connection error: {e}");
            }
            log::info!("[server] Connection closed");
        });
    }

    Ok(())
}

/// Per-session state, keyed by the raw QUIC stream ID of its request. One
/// QUIC connection can multiplex CONNECT-UDP and CONNECT-IP sessions.
enum Session {
    Udp(UdpSession),
    Ip(IpSession),
}

/// CONNECT-UDP session: keeps the stream alive and tracks the target socket.
struct UdpSession {
    target: Arc<UdpSocket>,
    /// Hold the CONNECT-UDP stream to prevent it from being dropped.
    /// RFC 9298 §3.2: the session lifetime is tied to the stream — dropping
    /// it sends FIN which terminates the session from the client's perspective.
    _stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    /// Abort handle for the spawned target reader task. UDP recv() never
    /// returns on its own when the client goes away, so we must explicitly
    /// abort the reader on session drop — otherwise the task keeps the
    /// Arc<UdpSocket> alive and leaks an fd per stale session.
    reader: tokio::task::AbortHandle,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn handle_connection(
    quinn_conn: quinn::Connection,
    auth_token: Option<String>,
    ip_state: Option<Arc<IpTunState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Clone for datagram I/O — h3-quinn takes ownership of one clone for H3 stream processing
    let dgram_conn = quinn_conn.clone();

    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let mut h3 = {
        let mut builder = h3::server::builder();
        builder.enable_extended_connect(true);
        builder.enable_datagram(true);
        builder
            .build::<h3_quinn::Connection, Bytes>(h3_conn)
            .await?
    };

    let mut sessions: HashMap<u64, Session> = HashMap::new();
    let (cleanup_tx, mut cleanup_rx) = mpsc::channel::<u64>(64);

    loop {
        tokio::select! {
            // Accept new H3 requests (also drives the H3 connection)
            result = h3.accept() => {
                match result {
                    Ok(Some(resolver)) => {
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                handle_request(
                                    req, stream, &mut sessions, &auth_token,
                                    &dgram_conn, &cleanup_tx, &ip_state,
                                ).await;
                            }
                            Err(e) => log::error!("[server] Request resolve error: {e}"),
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        log::error!("[server] H3 error: {e}");
                        break;
                    }
                }
            }
            // Client -> tunnel: decode DATAGRAM and forward by session kind
            result = dgram_conn.read_datagram() => {
                let data = result?;
                if let Some((stream_id, ctx, payload)) = decode_datagram_ctx(&data) {
                    match sessions.get(&stream_id) {
                        Some(Session::Udp(s)) => {
                            let _ = s.target.try_send(payload);
                        }
                        Some(Session::Ip(s)) => s.forward_upstream(ctx, payload),
                        None => log::trace!("[server] No session for stream_id={stream_id}"),
                    }
                }
            }
            // Session cleanup: remove closed sessions
            Some(stream_id) = cleanup_rx.recv() => {
                if sessions.remove(&stream_id).is_some() {
                    log::info!("[server] Session cleaned up: stream_id={stream_id}");
                }
            }
        }
    }

    let count = sessions.len();
    if count > 0 {
        log::info!("[server] Connection closing, dropping {count} remaining session(s)");
    }

    Ok(())
}

async fn handle_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    sessions: &mut HashMap<u64, Session>,
    auth_token: &Option<String>,
    dgram_conn: &quinn::Connection,
    cleanup_tx: &mpsc::Sender<u64>,
    ip_state: &Option<Arc<IpTunState>>,
) {
    let protocol = req
        .extensions()
        .get::<Protocol>()
        .map(|p| p.as_str().to_string());
    let is_connect = req.method() == http::Method::CONNECT;
    let is_connect_udp = is_connect && protocol.as_deref() == Some("connect-udp");
    // connect-ip requests are only supported when a pool was configured.
    let is_connect_ip =
        is_connect && protocol.as_deref() == Some("connect-ip") && ip_state.is_some();

    if !is_connect_udp && !is_connect_ip {
        let resp = http::Response::builder().status(405).body(()).unwrap();
        let _ = stream.send_response(resp).await;
        return;
    }

    // Auth check (shared by both extended-CONNECT protocols)
    if let Some(expected) = auth_token {
        let expected_header = format!("Bearer {expected}");
        let auth_ok = req
            .headers()
            .get("proxy-authorization")
            .and_then(|v| v.to_str().ok())
            == Some(&expected_header);
        if !auth_ok {
            log::warn!("[server] Auth failed");
            let resp = http::Response::builder().status(407).body(()).unwrap();
            let _ = stream.send_response(resp).await;
            return;
        }
    }

    if is_connect_ip {
        let path = req.uri().path().to_string();
        let state = ip_state.as_ref().expect("checked above");
        if let Some((stream_id, session)) =
            ip_server::handle_ip_request(state, &path, stream, dgram_conn, cleanup_tx).await
        {
            sessions.insert(stream_id, Session::Ip(session));
        }
        return;
    }

    // --- CONNECT-UDP (RFC 9298) from here on ---

    // Parse target from URI path
    let path = req.uri().path();
    let (host, port) = match parse_connect_udp_path(path) {
        Some(v) => v,
        None => {
            log::info!("[server] Invalid path: {path}");
            let resp = http::Response::builder().status(400).body(()).unwrap();
            let _ = stream.send_response(resp).await;
            return;
        }
    };

    // Resolve and connect to target. IP literals (including percent-decoded
    // IPv6) are used directly; only hostnames go through DNS resolution.
    let target_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        SocketAddr::new(ip, port)
    } else {
        match tokio::net::lookup_host(format!("{host}:{port}")).await {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    let resp = http::Response::builder().status(502).body(()).unwrap();
                    let _ = stream.send_response(resp).await;
                    return;
                }
            },
            Err(e) => {
                log::error!("[server] DNS error for {host}:{port}: {e}");
                let resp = http::Response::builder().status(502).body(()).unwrap();
                let _ = stream.send_response(resp).await;
                return;
            }
        }
    };

    let bind_addr = if target_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let target = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::error!("[server] Cannot bind target socket: {e}");
            let resp = http::Response::builder().status(502).body(()).unwrap();
            let _ = stream.send_response(resp).await;
            return;
        }
    };
    if let Err(e) = target.connect(target_addr).await {
        log::error!("[server] Cannot connect to {target_addr}: {e}");
        let resp = http::Response::builder().status(502).body(()).unwrap();
        let _ = stream.send_response(resp).await;
        return;
    }

    // Send 200 OK with capsule-protocol header (RFC 9297 §3.4)
    let resp = http::Response::builder()
        .status(200)
        .header("capsule-protocol", "?1")
        .header("server", IDENT)
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(resp).await {
        log::error!("[server] Failed to send 200: {e}");
        return;
    }

    // Use the raw QUIC stream ID for session tracking, because DATAGRAMs
    // carry Quarter Stream ID = quic_stream_id / 4, and decode_datagram
    // reconstructs the full QUIC stream ID via qsid * 4.
    // stream.send_id().index() returns quic_stream_id >> 2 which is NOT the
    // same as the raw QUIC stream ID (it's off by a factor of 4).
    let h3_index = stream.send_id().index();
    let quic_stream_id = h3_index * 4; // Reconstruct raw QUIC stream ID
    let target = Arc::new(target);

    log::info!(
        "[server] CONNECT-UDP established: h3_index={h3_index} quic_stream_id={quic_stream_id} target={target_addr}"
    );

    // Spawn target reader — encodes and sends DATAGRAMs directly on the QUIC
    // connection, bypassing any per-connection channel. quinn::Connection is
    // cheaply cloneable and send_datagram is internally synchronized, so each
    // session's reader writes out concurrently. On send failure (connection
    // closed) or recv error, the task exits and signals cleanup. The task is
    // also force-aborted via Session::drop when the session is removed.
    let conn_for_reader = dgram_conn.clone();
    let cleanup = cleanup_tx.clone();
    let reader_target = target.clone();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match reader_target.recv(&mut buf).await {
                Ok(len) => {
                    let dgram = encode_datagram(quic_stream_id, &buf[..len]);
                    match conn_for_reader.send_datagram(dgram) {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => {
                            log::trace!("[server] drop oversized datagram for stream_id={quic_stream_id}: {len} bytes");
                        }
                        Err(_) => break,
                    }
                }
                Err(e) => {
                    log::warn!("[server] Target recv error for stream_id={quic_stream_id}: {e}");
                    break;
                }
            }
        }
        let _ = cleanup.send(quic_stream_id).await;
    });

    // Store the session — importantly, this moves `stream` into the Session struct
    // so it stays alive for the duration of the CONNECT-UDP session.
    sessions.insert(
        quic_stream_id,
        Session::Udp(UdpSession {
            target,
            _stream: stream,
            reader: handle.abort_handle(),
        }),
    );
}

fn load_certs(
    path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>>
{
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    Ok(rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?)
}

fn load_key(
    path: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "no private key found in PEM file".into())
}
