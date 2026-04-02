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
    let sni = config.sni.unwrap_or_else(|| proxy_host.clone());

    // Parse target
    let (target_host, target_port) = parse_target(&config.target)?;

    // Resolve proxy address
    let proxy_addr = tokio::net::lookup_host(format!("{proxy_host}:{proxy_port}"))
        .await?
        .next()
        .ok_or_else(|| format!("DNS resolution failed for {proxy_host}:{proxy_port}"))?;

    // TLS config
    let client_crypto = build_tls_config(&config.ca, config.insecure)?;

    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(200_000));
    transport.datagram_send_buffer_size(200_000);
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .map_err(|e| format!("{e}"))?,
    ));
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
    let mut backoff_ms = 500u64;
    loop {
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
                        backoff_ms = 500;
                        conn
                    }
                    Err(connecting) => match connecting.await {
                        Ok(c) => {
                            log::info!("[client] QUIC connected (full handshake)");
                            backoff_ms = 500;
                            c
                        }
                        Err(e) => {
                            log::error!("[client] Connection failed: {e}");
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                            backoff_ms = (backoff_ms * 2).min(30_000);
                            continue;
                        }
                    },
                }
            }
            Err(e) => {
                log::error!("[client] Connect error: {e}");
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(30_000);
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
        )
        .await;

        log::warn!("[client] Connection lost: {err}, reconnecting in {backoff_ms}ms");
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        backoff_ms = (backoff_ms * 2).min(30_000);
    }
}

async fn run_tunnel(
    quinn_conn: &quinn::Connection,
    local: &UdpSocket,
    proxy_host: &str,
    target_host: &str,
    target_port: u16,
    auth_token: &Option<String>,
) -> Box<dyn std::error::Error + Send + Sync> {
    match run_tunnel_inner(quinn_conn, local, proxy_host, target_host, target_port, auth_token).await
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

    // Build CONNECT-UDP request (RFC 9298)
    let path = format!("{CONNECT_UDP_PATH}/{target_host}/{target_port}/");
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
        return Err(format!("CONNECT-UDP rejected: status {}", resp.status()).into());
    }

    // Use raw QUIC stream ID for DATAGRAM Quarter Stream ID encoding.
    // index() returns quic_stream_id >> 2, but encode_datagram needs
    // the full QUIC stream ID (it divides by 4 internally for QSID).
    let h3_index = stream.id().index();
    let quic_stream_id = h3_index * 4;
    log::info!(
        "[client] CONNECT-UDP established: h3_index={h3_index} quic_stream_id={quic_stream_id} target={target_host}:{target_port}"
    );

    // Datagram forwarding loop
    let mut peer_addr: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = local.recv_from(&mut buf) => {
                let (n, src) = result?;
                peer_addr = Some(src);
                let dgram = encode_datagram(quic_stream_id, &buf[..n]);
                dgram_conn.send_datagram(Bytes::from(dgram))?;
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

fn build_tls_config(
    ca: &Option<String>,
    insecure: bool,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else if let Some(ca_path) = ca {
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
        return Err("either --insecure or --ca must be specified".into());
    };
    config.alpn_protocols = vec![b"h3".to_vec()];
    config.enable_early_data = true;
    Ok(config)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
