//! Verifies that the client's TLS ClientHello does not fit in one QUIC Initial.
//!
//! The GFW's QUIC SNI filter decrypts the Initial packet — its keys derive from
//! the destination connection ID and a fixed salt, so they are not secret — and
//! reads the SNI. Per the USENIX Security 2025 measurement it inspects only the
//! *first* datagram of a flow and does not reassemble a ClientHello split
//! across several, so a handshake that spills past datagram one is not matched.
//!
//! Enabling rustls's `prefer-post-quantum` puts X25519MLKEM768 first, whose
//! ~1216-byte key share pushes the ClientHello over the ~1200-byte Initial
//! budget. That spill is the property under test: if a dependency bump or a
//! feature change silently shrinks the ClientHello again, the SNI quietly
//! returns to the first datagram and this fails.

use std::sync::Arc;
use std::time::Duration;

/// Longest a client's first flight can take to arrive on loopback. Well under
/// quinn's initial PTO (~333 ms), so no retransmission is counted as part of it.
const FLIGHT_WINDOW: Duration = Duration::from_millis(250);

fn client_config() -> quinn::ClientConfig {
    // Trust setup is irrelevant here — nothing answers — but the key exchange
    // groups are not, and those come from the process-wide rustls provider,
    // which is what `prefer-post-quantum` changes.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ))
}

/// Collect the datagrams a quinn client sends before giving up on a silent peer.
async fn capture_first_flight(server_name: &'static str) -> Vec<usize> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(client_config());
        // Nothing ever answers, so this just emits the initial flight.
        let _ = ep.connect(addr, server_name).unwrap().await;
    });

    let mut sizes = Vec::new();
    let deadline = tokio::time::Instant::now() + FLIGHT_WINDOW;
    let mut buf = vec![0u8; 4096];
    while let Ok(Ok((n, _))) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
        sizes.push(n);
    }
    sizes
}

#[tokio::test]
async fn client_hello_spills_past_the_first_datagram() {
    let sizes = capture_first_flight("sni-must-not-fit-in-datagram-one.example.com").await;

    assert!(
        !sizes.is_empty(),
        "captured no client packets at all — the test harness is broken, not the client"
    );
    assert!(
        sizes.len() >= 2,
        "ClientHello fit in {} datagram(s) of {:?} bytes; the SNI is back in the one datagram \
         the GFW inspects. Check that rustls still has the `prefer-post-quantum` feature.",
        sizes.len(),
        sizes,
    );
    // Every Initial is padded to at least the 1200-byte minimum (RFC 9000
    // §14.1), which is what makes a single-datagram ClientHello possible in the
    // first place; seeing the flight exceed one datagram means it genuinely
    // overflowed rather than being split for some other reason.
    assert!(
        sizes.iter().take(2).all(|&n| n >= 1200),
        "expected full-size Initial datagrams, got {sizes:?}"
    );
}

#[tokio::test]
async fn post_quantum_key_share_is_offered_first() {
    // The wire-level reason the ClientHello is large. Also the property that
    // makes the handshake resemble Chrome's and Firefox's, both of which lead
    // with X25519MLKEM768.
    let groups = rustls::crypto::aws_lc_rs::default_provider().kx_groups;
    let first = groups.first().expect("provider offers key exchange groups");
    assert_eq!(
        first.name(),
        rustls::NamedGroup::X25519MLKEM768,
        "expected the PQ hybrid first, got {:?}; without it the ClientHello shrinks back \
         under 1200 bytes and the SNI lands in the first datagram",
        first.name()
    );
}
