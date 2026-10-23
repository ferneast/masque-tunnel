//! The clients' default trust must actually verify.
//!
//! Default trust is the OS verifier, which this crate does not implement and
//! cannot see into: a wiring mistake there (a verifier that never runs, or one
//! that accepts everything) would look exactly like a working setup against a
//! real relay. A throwaway self-signed certificate is trusted by no OS, so the
//! default path has to refuse it; `--ca` naming that certificate and
//! `--insecure` have to accept it, which also shows the refusal comes from
//! verification and not from a handshake that never works.

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use masque_tunnel::common::build_client_tls_config;
use masque_tunnel::server::{self, ServerConfig};

/// Start a server with a fresh self-signed certificate for `localhost` on a
/// free loopback port; returns its address and the certificate's PEM path.
async fn spawn_server() -> (SocketAddr, PathBuf) {
    let port = UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tmp = std::env::temp_dir().join(format!("masq-trust-{port}"));
    std::fs::create_dir_all(&tmp).unwrap();
    let cert_path = tmp.join("cert.pem");
    let key_path = tmp.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let config = ServerConfig {
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
    };
    tokio::spawn(async move {
        let _ = server::run(config).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    (addr, cert_path)
}

/// Handshake with the server using the clients' own TLS config.
async fn handshake(
    addr: SocketAddr,
    ca: Option<String>,
    insecure: bool,
) -> Result<quinn::Connection, quinn::ConnectionError> {
    let crypto = build_client_tls_config(&ca, insecure).unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    )));
    tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(addr, "localhost").unwrap(),
    )
    .await
    .expect("handshake neither completed nor failed")
}

#[tokio::test]
async fn default_trust_refuses_a_certificate_no_os_trusts() {
    let (addr, _) = spawn_server().await;
    match handshake(addr, None, false).await {
        Err(quinn::ConnectionError::TransportError(e)) => {
            // rustls reports a failed verification to quinn as a TLS alert in
            // the CRYPTO_ERROR range (0x100 + alert). The certificate alerts
            // run from bad_certificate (42) to unknown_ca (48); a timeout, a
            // reset or any other alert means the verifier never decided.
            let alert = u64::from(e.code).wrapping_sub(0x100);
            assert!(
                (42..=48).contains(&alert),
                "expected a certificate alert, got {e}"
            );
            eprintln!("default trust refused the certificate: {e}");
        }
        Err(e) => panic!("expected a certificate rejection, got {e}"),
        Ok(_) => panic!("default trust accepted a self-signed certificate"),
    }
}

#[tokio::test]
async fn ca_pins_the_named_certificate() {
    let (addr, cert_path) = spawn_server().await;
    let ca = Some(cert_path.to_string_lossy().into_owned());
    handshake(addr, ca, false)
        .await
        .expect("--ca must trust its own certificate");
}

#[tokio::test]
async fn insecure_skips_verification() {
    let (addr, _) = spawn_server().await;
    handshake(addr, None, true)
        .await
        .expect("--insecure must accept any certificate");
}
