//! End-to-end checks that an unauthenticated probe sees a website, not a proxy.
//!
//! The unit tests in `src/masquerade.rs` cover which status and body a path
//! resolves to. These drive a real server over a real QUIC connection, which
//! is the only way to confirm the parts that only exist on the wire: that a
//! plain GET reaches the decoy at all, and that h3 will carry a response body
//! on an extended-CONNECT stream (the path a rejected tunnel request takes).

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use masque_tunnel::server::{self, ServerConfig};

/// Accept any certificate: these tests generate a throwaway self-signed one and
/// are checking HTTP behavior, not trust.
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

/// A response as seen by a probe.
struct Probe {
    status: u16,
    headers: http::HeaderMap,
    body: Bytes,
}

/// Start a server on a free loopback port and return its address.
///
/// The port is taken by binding and immediately releasing a socket. There is a
/// theoretical race with another process claiming it in between; on a loopback
/// test host it has not been worth a more elaborate handshake.
fn spawn_server(
    dir: Option<String>,
    url: Option<String>,
    server_header: Option<String>,
    auth_token: Option<String>,
) -> SocketAddr {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tmp = std::env::temp_dir().join(format!("masq-e2e-{port}"));
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
            auth_token,
            ip_pool: None,
            ip6_pool: None,
            ip_mtu: 1280,
            ip_tun_name: None,
            ip_routes_file: None,
            dns_assign: Vec::new(),
            ip_allow_private: false,
            masquerade_dir: dir,
            masquerade_url: url,
            server_header,
        })
        .await;
    });

    addr
}

/// Send one request and collect the full response.
///
/// `protocol` set makes it an extended CONNECT — the shape a tunnel request
/// takes, and therefore the shape a rejected one takes too.
async fn probe(
    addr: SocketAddr,
    method: &str,
    path: &str,
    protocol: Option<&str>,
    auth: Option<&str>,
) -> Probe {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    )));

    let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"));
    if let Some(token) = auth {
        builder = builder.header("proxy-authorization", token);
    }
    let req = match protocol {
        Some(p) => {
            let ext: h3::ext::Protocol = p.parse().ok().expect("valid :protocol");
            builder.extension(ext).body(()).unwrap()
        }
        None => builder.body(()).unwrap(),
    };

    let mut stream = send_request.send_request(req).await.unwrap();
    // A plain request has no body; an extended CONNECT must keep its stream
    // open, since RFC 9298 ties the session lifetime to it.
    if protocol.is_none() {
        stream.finish().await.unwrap();
    }
    let resp = stream.recv_response().await.unwrap();

    // An accepted CONNECT is followed by capsules, not a body — reading here
    // would block until the session ends. Every other outcome is a decoy
    // response, which is exactly what these tests want to inspect.
    let established_tunnel = protocol.is_some() && resp.status() == 200;
    let mut body = Vec::new();
    if !established_tunnel {
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }
    }

    Probe {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: Bytes::from(body),
    }
}

/// The server task needs a moment to bind before the first connect.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn plain_get_reaches_the_decoy_site() {
    let addr = spawn_server(None, None, None, Some("secret".into()));
    settle().await;

    let root = probe(addr, "GET", "/", None, None).await;
    assert_eq!(root.status, 200);
    assert_eq!(
        root.headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(root.headers.contains_key("date"), "a web server sends Date");
    assert!(root.body.starts_with(b"<!DOCTYPE html>"));

    let missing = probe(addr, "GET", "/wp-login.php", None, None).await;
    assert_eq!(missing.status, 404);
    assert!(missing.body.starts_with(b"<!DOCTYPE html>"));
}

#[tokio::test]
async fn nothing_on_the_wire_names_the_product() {
    let addr = spawn_server(None, None, None, Some("secret".into()));
    settle().await;

    for (method, path, proto) in [
        ("GET", "/", None),
        ("GET", "/x", None),
        ("CONNECT", "/.well-known/masque/udp/1.1.1.1/443/", Some("connect-udp")),
    ] {
        let r = probe(addr, method, path, proto, Some("Bearer wrong")).await;
        assert!(
            !r.headers.contains_key("server"),
            "no Server header unless the operator sets one"
        );
        let text = String::from_utf8_lossy(&r.body).to_ascii_lowercase();
        assert!(!text.contains("masque"), "body leaked the product name");
    }
}

#[tokio::test]
async fn a_wrong_token_is_answered_by_the_decoy_not_a_407() {
    // The whole point: a prober with a bad token must see the same web
    // response it would get by fetching that URL with no token at all. If
    // these diverge, the prober has confirmed a proxy.
    let addr = spawn_server(None, None, None, Some("secret".into()));
    settle().await;

    let path = "/.well-known/masque/udp/1.1.1.1/443/";
    let bad_token = probe(addr, "CONNECT", path, Some("connect-udp"), Some("Bearer wrong")).await;
    let no_token = probe(addr, "CONNECT", path, Some("connect-udp"), None).await;
    let plain_get = probe(addr, "GET", path, None, None).await;

    assert_eq!(bad_token.status, 404, "must not be 407/405");
    assert_eq!(bad_token.status, no_token.status);
    assert_eq!(bad_token.body, no_token.body);
    assert_eq!(bad_token.status, plain_get.status);
    assert_eq!(
        bad_token.body, plain_get.body,
        "a rejected tunnel request must be indistinguishable from a plain fetch"
    );
    // Body on an extended-CONNECT stream has to actually arrive, otherwise the
    // decoy is empty exactly where it matters most.
    assert!(!bad_token.body.is_empty());
}

#[tokio::test]
async fn decoy_serves_a_directory_and_refuses_traversal() {
    let dir = std::env::temp_dir().join("masq-e2e-site");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<!DOCTYPE html><h1>real site</h1>").unwrap();
    let secret = dir.parent().unwrap().join("masq-e2e-secret.txt");
    std::fs::write(&secret, "TOPSECRET").unwrap();

    let addr = spawn_server(
        Some(dir.to_string_lossy().into_owned()),
        None,
        Some("nginx".into()),
        None,
    );
    settle().await;

    let root = probe(addr, "GET", "/", None, None).await;
    assert_eq!(root.status, 200);
    assert_eq!(root.body, Bytes::from_static(b"<!DOCTYPE html><h1>real site</h1>"));
    assert_eq!(root.headers.get("server").unwrap(), "nginx");

    let escape = probe(addr, "GET", "/%2e%2e/masq-e2e-secret.txt", None, None).await;
    assert_eq!(escape.status, 404);
    assert!(!escape.body.windows(9).any(|w| w == b"TOPSECRET"));

    let _ = std::fs::remove_file(&secret);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn decoy_can_redirect_everything_to_a_real_site() {
    let addr = spawn_server(None, Some("https://example.com/".into()), None, Some("s".into()));
    settle().await;

    for (method, path, proto) in [
        ("GET", "/", None),
        ("CONNECT", "/.well-known/masque/udp/1.1.1.1/443/", Some("connect-udp")),
    ] {
        let r = probe(addr, method, path, proto, None).await;
        assert_eq!(r.status, 302);
        assert_eq!(r.headers.get("location").unwrap(), "https://example.com/");
    }
}

#[tokio::test]
async fn a_valid_token_still_establishes_a_tunnel() {
    // The decoy must not have swallowed the real path.
    let addr = spawn_server(None, None, None, Some("secret".into()));
    settle().await;

    let ok = probe(
        addr,
        "CONNECT",
        "/.well-known/masque/udp/127.0.0.1/9/",
        Some("connect-udp"),
        Some("Bearer secret"),
    )
    .await;
    assert_eq!(ok.status, 200);
    assert_eq!(ok.headers.get("capsule-protocol").unwrap(), "?1");
}

#[tokio::test]
async fn the_bundled_example_site_serves_correctly() {
    // examples/decoy-site is what production points --masquerade-dir at, so a
    // broken file there is a broken decoy on every relay.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/decoy-site");
    let addr = spawn_server(Some(dir.into()), None, Some("nginx".into()), Some("s".into()));
    settle().await;

    let root = probe(addr, "GET", "/", None, None).await;
    assert_eq!(root.status, 200);
    assert_eq!(
        root.headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(root.body.starts_with(b"<!DOCTYPE html>"));

    // Assets the page references must resolve, or a prober fetching them gets
    // 404s that a real site would not produce.
    for (path, ctype) in [
        ("/style.css", "text/css; charset=utf-8"),
        ("/favicon.svg", "image/svg+xml"),
        ("/robots.txt", "text/plain; charset=utf-8"),
        ("/status.json", "application/json"),
    ] {
        let r = probe(addr, "GET", path, None, None).await;
        assert_eq!(r.status, 200, "{path} must resolve");
        assert_eq!(r.headers.get("content-type").unwrap(), ctype, "{path}");
        assert!(!r.body.is_empty(), "{path} must not be empty");
    }

    // And nothing in it may name the product.
    let text = String::from_utf8_lossy(&root.body).to_ascii_lowercase();
    for bad in ["masque", "tunnel", "vpn", "proxy"] {
        assert!(!text.contains(bad), "example site leaked {bad:?}");
    }
}
