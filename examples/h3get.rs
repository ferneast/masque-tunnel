//! Fetch a URL over HTTP/3 and print the response, the way a censor's active
//! probe would see it.
//!
//! There is no widely-installed HTTP/3 curl, so verifying that a deployed relay
//! actually looks like a web server needs its own tool. Prints status, headers,
//! and the body so an operator can eyeball what a prober gets.
//!
//! ```text
//! cargo run --example h3get -- https://relay.example.com/
//! cargo run --example h3get -- https://relay.example.com/style.css --head
//! ```

use std::sync::Arc;

use bytes::Buf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    let url = args
        .get(1)
        .ok_or("usage: h3get <https://host[:port]/path> [--head] [--insecure]")?;
    let head_only = args.iter().any(|a| a == "--head");
    let insecure = args.iter().any(|a| a == "--insecure");

    let parsed = url::Url::parse(url)?;
    let host = parsed.host_str().ok_or("missing host")?.to_string();
    let port = parsed.port().unwrap_or(443);
    let path = if parsed.path().is_empty() {
        "/".to_string()
    } else {
        parsed.path().to_string()
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let addr = tokio::net::lookup_host(format!("{host}:{port}"))
        .await?
        .next()
        .ok_or("DNS resolution failed")?;
    let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };

    let mut endpoint = quinn::Endpoint::client(bind.parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )));

    let conn = endpoint.connect(addr, &host)?.await?;
    println!("connected to {addr}");

    let (mut driver, mut send_request) =
        h3::client::new(h3_quinn::Connection::new(conn)).await?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });

    let req = http::Request::builder()
        .method(if head_only { "HEAD" } else { "GET" })
        .uri(format!("https://{host}{path}"))
        .body(())?;

    let mut stream = send_request.send_request(req).await?;
    stream.finish().await?;
    let resp = stream.recv_response().await?;

    println!("\nHTTP/3 {}", resp.status());
    for (name, value) in resp.headers() {
        println!("{name}: {}", value.to_str().unwrap_or("<binary>"));
    }

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }
    if !body.is_empty() {
        println!("\n--- body ({} bytes) ---", body.len());
        println!("{}", String::from_utf8_lossy(&body));
    }
    Ok(())
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
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
