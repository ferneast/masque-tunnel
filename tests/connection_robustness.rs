//! A misbehaving-looking-but-legal stream must not take down the connection.
//!
//! RFC 9114 does not require a client to send HEADERS promptly after opening a
//! request stream, and at least one real client does not: Apple's
//! Network.framework opens a client-initiated bidirectional stream 0 that never
//! carries any. The server used to await header resolution inline in its
//! `select!` loop, so that one stream froze everything on the connection —
//! further requests were never accepted and datagram forwarding stopped too.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use masque_tunnel::server::{self, ServerConfig};

/// Accept any certificate: this test generates a throwaway self-signed one and
/// is checking connection behavior, not trust.
#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Start a server with the built-in decoy site on a free loopback port.
fn spawn_server() -> SocketAddr {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tmp = std::env::temp_dir().join(format!("masq-robust-{port}"));
    std::fs::create_dir_all(&tmp).unwrap();
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    tokio::spawn(async move {
        let _ = server::run(ServerConfig {
            listen: addr.to_string(),
            cert: cert_path.to_string_lossy().into_owned(),
            key: key_path.to_string_lossy().into_owned(),
            auth_token: None,
            ip_pool: None,
            ip6_pool: None,
            ip_mtu: 1280,
            ip_tun_name: None,
            ip_routes_file: None,
            dns_assign: Vec::new(),
            ip_allow_private: false,
            masquerade_dir: None,
            masquerade_url: None,
            server_header: None,
        })
        .await;
    });

    addr
}

fn client_endpoint() -> quinn::Endpoint {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    )));
    endpoint
}

#[tokio::test]
async fn a_request_stream_without_headers_does_not_wedge_the_connection() {
    let addr = spawn_server();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let endpoint = client_endpoint();
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    // The h3 layer takes one clone; the other opens the raw stream behind h3's
    // back, which is the only way to produce a request stream h3 would never
    // create itself.
    let raw = conn.clone();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    // Open a request stream and send a lone HEADERS frame *type* with no length
    // and no payload. The server accepts the stream but can never finish
    // resolving its headers. Held for the whole test: dropping it would reset
    // the stream and release the wedge, which is what we must not depend on.
    let (mut wedge, _wedge_recv) = raw.open_bi().await.unwrap();
    wedge.write_all(&[0x01]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // A normal request on the same connection must still be served.
    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();

    let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .expect("server must answer while a headerless request stream is outstanding")
        .unwrap();
    assert_eq!(resp.status(), 200);

    drop(wedge);
}

#[tokio::test]
async fn several_headerless_streams_still_leave_the_connection_usable() {
    let addr = spawn_server();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let endpoint = client_endpoint();
    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let raw = conn.clone();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let mut wedges = Vec::new();
    for _ in 0..8 {
        let (mut send, _recv) = raw.open_bi().await.unwrap();
        send.write_all(&[0x01]).await.unwrap();
        wedges.push(send);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    for path in ["/", "/wp-login.php"] {
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://localhost{path}"))
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.unwrap();
        stream.finish().await.unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
            .await
            .expect("server must keep answering with several headerless streams outstanding")
            .unwrap();
        assert!(resp.status() == 200 || resp.status() == 404);
    }

    drop(wedges);
}
