use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;

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

/// Run the MASQUE CONNECT-UDP client with automatic reconnection.
pub async fn run(config: ClientConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr: SocketAddr = config.listen.parse()?;

    // Parse proxy URL
    let url = url::Url::parse(&config.proxy_url)?;
    let proxy_host = url.host_str().ok_or("missing host in proxy URL")?.to_string();
    let proxy_port = url.port().unwrap_or(443);
    let sni = config
        .sni
        .unwrap_or_else(|| unbracket_host(&proxy_host).to_string());

    // Parse target
    let (target_host, target_port) = parse_target(&config.target)?;

    // Resolve proxy address
    let proxy_addr = tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}"))
        .await?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {proxy_host}:{proxy_port}"))?;

    // TLS config
    let client_crypto = build_client_tls_config(&config.ca, config.insecure)?;

    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1350);
    transport.datagram_receive_buffer_size(Some(8_000_000));
    transport.datagram_send_buffer_size(8_000_000);
    // Must match the server's advertised value: the effective idle timeout is the
    // minimum of the two. See the note in server.rs — the host process is
    // throttled while the device is idle, so the keep-alive below does not
    // actually fire on its nominal interval and the timeout has to cover the gap.
    transport.max_idle_timeout(Some(
        Duration::from_secs(120)
            .try_into()
            .map_err(|e| format!("{e}"))?,
    ));
    // Send PING frames well under max_idle_timeout so an idle tunnel (e.g. an
    // inner WireGuard flow with no traffic) doesn't churn a reconnect whenever
    // it goes quiet.
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(Arc::new(transport));

    let bind_addr: SocketAddr = if proxy_addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let local = UdpSocket::bind(listen_addr).await?;
    log::info!(
        "[client] Listening on {listen_addr}, proxy={proxy_host}:{proxy_port}, target={target_host}:{target_port}"
    );

    // Reconnection loop
    let mut backoff = Backoff::new();
    loop {
        // Set by run_tunnel once the CONNECT-UDP session is actually running.
        let mut established = false;

        log::info!("[client] Connecting to {proxy_addr}...");
        let quinn_conn = match endpoint.connect(proxy_addr, &sni) {
            Ok(connecting) => {
                // Try 0-RTT first (requires a cached session ticket from a previous connection)
                match connecting.into_0rtt() {
                    Ok((conn, zero_rtt_accepted)) => {
                        log::info!("[client] 0-RTT connection (early data)");
                        tokio::spawn(async move {
                            zero_rtt_accepted.await;
                            log::info!("[client] 0-RTT accepted by server");
                        });
                        conn
                    }
                    Err(connecting) => match connecting.await {
                        Ok(c) => {
                            log::info!("[client] QUIC connected (full handshake)");
                            c
                        }
                        Err(e) => {
                            log::error!("[client] Connection failed: {e}");
                            tokio::time::sleep(backoff.next(false)).await;
                            continue;
                        }
                    },
                }
            }
            Err(e) => {
                log::error!("[client] Connect error: {e}");
                tokio::time::sleep(backoff.next(false)).await;
                continue;
            }
        };

        let err = run_tunnel(
            &quinn_conn,
            &local,
            &proxy_host,
            &target_host,
            target_port,
            &config.auth_token,
            &mut established,
        )
        .await;

        let wait = backoff.next(established);
        log::warn!(
            "[client] Connection lost: {err}, reconnecting in {}ms",
            wait.as_millis()
        );
        tokio::time::sleep(wait).await;
    }
}

async fn run_tunnel(
    quinn_conn: &quinn::Connection,
    local: &UdpSocket,
    proxy_host: &str,
    target_host: &str,
    target_port: u16,
    auth_token: &Option<String>,
    established: &mut bool,
) -> Box<dyn std::error::Error + Send + Sync> {
    match run_tunnel_inner(
        quinn_conn,
        local,
        proxy_host,
        target_host,
        target_port,
        auth_token,
        established,
    )
    .await
    {
        Ok(()) => "tunnel ended".into(),
        Err(e) => e,
    }
}

async fn run_tunnel_inner(
    quinn_conn: &quinn::Connection,
    local: &UdpSocket,
    proxy_host: &str,
    target_host: &str,
    target_port: u16,
    auth_token: &Option<String>,
    // Set once the proxy has accepted the session, so the caller can tell a
    // healthy connection that dropped from one that never worked at all.
    established: &mut bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Clone for datagram I/O — h3-quinn takes ownership of one clone
    let dgram_conn = quinn_conn.clone();

    let h3_conn = h3_quinn::Connection::new(quinn_conn.clone());
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build::<h3_quinn::Connection, h3_quinn::OpenStreams, Bytes>(h3_conn)
        .await?;

    // Spawn H3 driver to keep the connection alive
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Build CONNECT-UDP request (RFC 9298). The target host is percent-encoded
    // so IPv6 literals (colons -> %3A, brackets dropped) form a valid path segment.
    let encoded_host = encode_target_host(target_host);
    let path = format!("{CONNECT_UDP_PATH}/{encoded_host}/{target_port}/");
    let uri: http::Uri = format!("https://{proxy_host}{path}").parse()?;
    let protocol: h3::ext::Protocol = "connect-udp"
        .parse()
        .map_err(|_| "invalid protocol")?;

    let mut req_builder = http::Request::builder()
        .method("CONNECT")
        .uri(uri)
        .header("capsule-protocol", "?1");
    if let Some(token) = auth_token {
        req_builder = req_builder.header("proxy-authorization", format!("Bearer {token}"));
    }
    let req = req_builder.extension(protocol).body(())?;

    let mut stream = send_request.send_request(req).await?;
    let resp = stream.recv_response().await?;

    if resp.status() != http::StatusCode::OK {
        // The proxy answers every unauthenticated request from its decoy site,
        // so a rejected session looks like an ordinary web response and cannot
        // name the reason — that indistinguishability is the point. Spell out
        // the candidates, or a 404 here reads as a wrong path and nothing else.
        return Err(format!(
            "CONNECT-UDP rejected: status {} (check --auth-token and --proxy-url; \
             the proxy serves its decoy site to any request it does not accept)",
            resp.status()
        )
        .into());
    }
    if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
        log::info!("[client] proxy server: {server}");
    }

    // Use raw QUIC stream ID for DATAGRAM Quarter Stream ID encoding.
    // index() returns quic_stream_id >> 2, but encode_datagram needs
    // the full QUIC stream ID (it divides by 4 internally for QSID).
    let h3_index = stream.id().index();
    let quic_stream_id = h3_index * 4;
    log::info!(
        "[client] CONNECT-UDP established: h3_index={h3_index} quic_stream_id={quic_stream_id} target={target_host}:{target_port}"
    );
    // The proxy accepted the session: this attempt genuinely connected, so the
    // reconnect loop may restart its backoff from the floor.
    *established = true;

    // Datagram forwarding loop
    let mut peer_addr: Option<SocketAddr> = None;
    let mut buf = [0u8; 2048];

    loop {
        tokio::select! {
            result = local.recv_from(&mut buf) => {
                let (n, src) = result?;
                peer_addr = Some(src);
                match dgram_conn.send_datagram(encode_datagram(quic_stream_id, &buf[..n])) {
                    Ok(()) => {}
                    Err(quinn::SendDatagramError::TooLarge) => {
                        log::trace!("[client] drop oversized datagram: {n} bytes");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            result = dgram_conn.read_datagram() => {
                let data = result?;
                if let Some((_, payload)) = decode_datagram(&data) {
                    if let Some(addr) = peer_addr {
                        local.send_to(payload, addr).await?;
                    }
                }
            }
        }
    }
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


