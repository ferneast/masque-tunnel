use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};

/// Build the client TLS config both clients share.
///
/// Trust resolves in three steps: `--insecure` disables verification
/// entirely, `--ca` pins a private root store, and the default is the Mozilla
/// CA bundle — which includes the ISRG roots that real ACME/Let's Encrypt
/// certificates chain to, so a public relay verifies with no extra flags and
/// no platform trust glue (the iOS build has none available).
///
/// Shared rather than duplicated because both clients need byte-identical
/// behavior here, and a trust decision that drifts between two copies is the
/// kind of bug that fails open.
pub fn build_client_tls_config(
    ca: &Option<String>,
    insecure: bool,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        match ca {
            Some(path) => {
                let file = std::fs::File::open(path)?;
                let mut reader = std::io::BufReader::new(file);
                for cert in rustls_pemfile::certs(&mut reader) {
                    roots.add(cert?)?;
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h3".to_vec()];
    // Allow 0-RTT on reconnect: the rustls session store persists tickets, so a
    // resumed handshake sends its CONNECT request as early data and reaches the
    // tunnel one RTT sooner. quinn falls back to 1-RTT if the server refuses.
    config.enable_early_data = true;
    Ok(config)
}

/// Accepts any certificate. Only reachable via `--insecure`, for self-signed
/// test deployments.
#[derive(Debug)]
pub struct SkipServerVerification;

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
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Reconnect pacing, shared by both clients: the wait doubles after every
/// attempt that did not run a session, up to a ceiling, and drops back to the
/// floor once one did.
///
/// The distinction is the whole point, and it is about the *session*, not the
/// QUIC handshake. A proxy rejects a bad request — wrong token, wrong path,
/// CONNECT-IP with no pool — only after the handshake has already succeeded,
/// so pacing on the handshake makes a permanently broken config reconnect
/// twice a second forever: useless load on the proxy, and a metronome-regular
/// pattern that stands out to anyone watching the flow.
pub struct Backoff(u64);

impl Backoff {
    pub const FLOOR_MS: u64 = 500;
    pub const CEILING_MS: u64 = 30_000;

    pub fn new() -> Self {
        Self(Self::FLOOR_MS)
    }

    /// Wait before the next attempt, given whether the last one ran a session.
    pub fn next(&mut self, established: bool) -> Duration {
        if established {
            self.0 = Self::FLOOR_MS;
        }
        let wait = self.0;
        self.0 = (self.0 * 2).min(Self::CEILING_MS);
        Duration::from_millis(wait)
    }

    /// Return to the floor without consuming an attempt.
    ///
    /// For a reconnect that is known to be worth trying immediately — the
    /// CONNECT-IP client does this when the host signals a network path change,
    /// where the previous failure says nothing about the new path.
    pub fn reset(&mut self) {
        self.0 = Self::FLOOR_MS;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new()
    }
}

// This crate deliberately puts no product identity on the wire. A `Server:` or
// `User-Agent:` naming it hands an exact identification to any probe that
// reaches either end, so the server's header is operator-configured
// (`--server-header`, empty by default) and the client sends none at all.

/// Well-known URI prefix for CONNECT-UDP (RFC 9298).
pub const CONNECT_UDP_PATH: &str = "/.well-known/masque/udp";

/// Well-known URI prefix for CONNECT-IP (RFC 9484).
pub const CONNECT_IP_PATH: &str = "/.well-known/masque/ip";

/// Largest inner IP packet one HTTP Datagram can carry before we reply with an
/// ICMP Packet Too Big (RFC 9484 §7.1). Kept below the datagram payload
/// available at the initial ~1350-byte max UDP payload (leaving room for QUIC,
/// DATAGRAM-frame, quarter-stream-id, and context-id overhead) and at/above
/// the IPv6 minimum MTU of 1280.
pub const TUNNEL_IP_MTU: u32 = 1300;

/// Strip the brackets `Url::host_str` keeps around an IPv6 literal. They belong
/// in a URI authority but break both name resolution and TLS, which expect the
/// bare address.
pub fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

/// Append a QUIC variable-length integer (RFC 9000, Section 16) to a buffer.
pub fn put_varint(buf: &mut BytesMut, value: u64) {
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u16((value as u16) | 0x4000);
    } else if value < 1_073_741_824 {
        buf.put_u32((value as u32) | 0x80000000);
    } else {
        buf.put_u64(value | 0xC000000000000000);
    }
}

/// Decode a QUIC variable-length integer. Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let value = match len {
        1 => (first & 0x3F) as u64,
        2 => {
            let mut bytes = [0u8; 2];
            bytes.copy_from_slice(&buf[..2]);
            bytes[0] &= 0x3F;
            u16::from_be_bytes(bytes) as u64
        }
        4 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&buf[..4]);
            bytes[0] &= 0x3F;
            u32::from_be_bytes(bytes) as u64
        }
        8 => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&buf[..8]);
            bytes[0] &= 0x3F;
            u64::from_be_bytes(bytes)
        }
        _ => return None,
    };
    Some((value, len))
}

/// Encode a DATAGRAM payload with Quarter Stream ID and Context ID = 0.
/// Returns Bytes via BytesMut::freeze (single allocation, O(1) handoff).
pub fn encode_datagram(stream_id: u64, payload: &[u8]) -> Bytes {
    encode_datagram_ctx(stream_id, 0, payload)
}

/// Encode a DATAGRAM payload with an explicit Context ID. Context 0 carries the
/// proxied payload; the CONNECT-IP client uses a non-zero context for an empty
/// ack-eliciting keepalive that the proxy drops instead of forwarding.
pub fn encode_datagram_ctx(stream_id: u64, context_id: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(9 + payload.len());
    put_varint(&mut buf, stream_id / 4);
    put_varint(&mut buf, context_id);
    buf.put_slice(payload);
    buf.freeze()
}

/// Decrement an IP packet's TTL (IPv4) / Hop Limit (IPv6) in place, as required
/// upon encapsulating a forwarded packet into an HTTP Datagram (RFC 9484 §7.1:
/// "the Hop Count is decremented right before an IP packet is transmitted in an
/// HTTP Datagram"). Only the CONNECT-IP client's upstream path needs this: the
/// server relies on the kernel's IP-forwarding to decrement transited packets,
/// so decrementing there too would double-count.
///
/// Returns `true` if the packet may be forwarded, or `false` if the hop count
/// is exhausted (was 0 or 1) and the packet must be dropped. Buffers that are
/// not recognizable IPv4/IPv6 are left unchanged and forwarded (`true`) — this
/// only ever sees packets read off the TUN, which are transited traffic. For
/// IPv4 the header checksum is recomputed over the header length (IHL).
pub fn decrement_hop_limit(pkt: &mut [u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            if ihl < 20 || pkt.len() < ihl {
                return false; // malformed IPv4 header
            }
            if pkt[8] <= 1 {
                return false; // TTL would reach 0
            }
            pkt[8] -= 1;
            // Recompute the header checksum (RFC 1071) over the full IHL so
            // options, if any, are covered.
            pkt[10] = 0;
            pkt[11] = 0;
            let mut sum = 0u32;
            let mut i = 0;
            while i + 1 < ihl {
                sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
                i += 2;
            }
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let ck = !(sum as u16);
            pkt[10..12].copy_from_slice(&ck.to_be_bytes());
            true
        }
        Some(6) if pkt.len() >= 40 => {
            if pkt[7] <= 1 {
                return false; // Hop Limit would reach 0
            }
            pkt[7] -= 1;
            true
        }
        _ => true, // not a recognized IP packet; forward unchanged
    }
}

/// Decode a DATAGRAM payload. Returns (stream_id, udp_payload).
pub fn decode_datagram(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (stream_id, _, payload) = decode_datagram_ctx(buf)?;
    Some((stream_id, payload))
}

/// Decode a DATAGRAM payload keeping the context ID:
/// (stream_id, context_id, payload). RFC 9298/9484 reserve Context ID 0 for
/// the proxied payload; callers must drop datagrams with any other value.
pub fn decode_datagram_ctx(buf: &[u8]) -> Option<(u64, u64, &[u8])> {
    let (qsid, qsid_len) = decode_varint(buf)?;
    let stream_id = qsid * 4;
    let remaining = &buf[qsid_len..];
    let (ctx, ctx_len) = decode_varint(remaining)?;
    Some((stream_id, ctx, &remaining[ctx_len..]))
}

/// Percent-decode an ASCII URI component (RFC 3986). Invalid `%` escapes are
/// left untouched. Used to recover the target host from a CONNECT-UDP path,
/// where IPv6 literals arrive with their colons encoded as `%3A` (RFC 9298).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encode a target host for use as a CONNECT-UDP path segment (RFC 9298).
///
/// IPv6 literal brackets are dropped and reserved characters (notably the
/// IPv6 colon) are percent-encoded, so `[2a14::1]` becomes `2a14%3A%3A1`.
pub fn encode_target_host(host: &str) -> String {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let mut out = String::with_capacity(bare.len());
    for &b in bare.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse a CONNECT-UDP path `/.well-known/masque/udp/{host}/{port}/` into (host, port).
///
/// The host is percent-decoded (RFC 9298 encodes IPv6 literal colons as `%3A`)
/// and any surrounding brackets are stripped, so callers receive a bare host or
/// IP literal ready for connection.
pub fn parse_connect_udp_path(path: &str) -> Option<(String, u16)> {
    let prefix = format!("{}/", CONNECT_UDP_PATH);
    let stripped = path.strip_prefix(&prefix)?;
    let stripped = stripped.strip_suffix('/').unwrap_or(stripped);
    let last_slash = stripped.rfind('/')?;
    let host = &stripped[..last_slash];
    let port: u16 = stripped[last_slash + 1..].parse().ok()?;
    if host.is_empty() {
        return None;
    }
    let mut host = percent_decode(host);
    // Tolerate clients that send bracketed IPv6 literals (RFC 9298 omits the
    // brackets, but bracketed forms are common in the wild).
    if host.starts_with('[') && host.ends_with(']') {
        host = host[1..host.len() - 1].to_string();
    }
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// Parse a CONNECT-IP path `/.well-known/masque/ip/{target}/{ipproto}/` into
/// its percent-decoded (target, ipproto) segments (RFC 9484 §4.1).
///
/// Both variables may be the wildcard `*`. Validation of scoped targets and
/// protocol numbers is left to the caller; this only recovers the segments.
pub fn parse_connect_ip_path(path: &str) -> Option<(String, String)> {
    let prefix = format!("{}/", CONNECT_IP_PATH);
    let stripped = path.strip_prefix(&prefix)?;
    let stripped = stripped.strip_suffix('/').unwrap_or(stripped);
    let mut parts = stripped.split('/');
    let target = parts.next()?;
    let ipproto = parts.next()?;
    if parts.next().is_some() || target.is_empty() || ipproto.is_empty() {
        return None;
    }
    Some((percent_decode(target), percent_decode(ipproto)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waits(b: &mut Backoff, n: usize, established: bool) -> Vec<u64> {
        (0..n)
            .map(|_| b.next(established).as_millis() as u64)
            .collect()
    }

    #[test]
    fn backoff_doubles_up_to_the_ceiling_while_nothing_connects() {
        let mut b = Backoff::new();
        assert_eq!(
            waits(&mut b, 8, false),
            [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000]
        );
    }

    #[test]
    fn a_session_that_ran_returns_the_wait_to_the_floor() {
        let mut b = Backoff::new();
        waits(&mut b, 5, false); // climb to 16s
        assert_eq!(b.next(true).as_millis(), 500);
    }

    #[test]
    fn a_rejected_session_never_pins_the_wait_at_the_floor() {
        // The regression this guards. Resetting the backoff on a completed QUIC
        // handshake — rather than on a session that actually ran — made a wrong
        // --auth-token reconnect every 500ms indefinitely, because the proxy
        // only rejects the request after the handshake succeeds.
        let mut b = Backoff::new();
        let observed = waits(&mut b, 6, false);
        assert!(
            observed.iter().skip(1).all(|&w| w > Backoff::FLOOR_MS),
            "every wait after the first must have grown, got {observed:?}"
        );
    }

    #[test]
    fn reset_returns_to_the_floor_without_consuming_an_attempt() {
        // What the CONNECT-IP client does on a network path change: the new
        // path deserves an immediate try, and the next wait after it starts
        // over rather than resuming the old climb.
        let mut b = Backoff::new();
        waits(&mut b, 4, false); // climb to 8s
        b.reset();
        assert_eq!(waits(&mut b, 2, false), [500, 1000]);
    }

    fn p(path: &str) -> Option<(String, u16)> {
        parse_connect_udp_path(path)
    }

    #[test]
    fn unbracket_host_handles_every_host_form() {
        // What `Url::host_str` hands back for an IPv6 literal proxy URL. The
        // bracketed form reaches getaddrinfo as a hostname and fails there.
        let host = url::Url::parse("https://[2001:db8::1]:443")
            .unwrap()
            .host_str()
            .unwrap()
            .to_string();
        assert_eq!(host, "[2001:db8::1]");
        assert_eq!(unbracket_host(&host), "2001:db8::1");
        assert!(unbracket_host(&host).parse::<std::net::Ipv6Addr>().is_ok());

        assert_eq!(unbracket_host("example.com"), "example.com");
        assert_eq!(unbracket_host("192.0.2.6"), "192.0.2.6");
    }

    #[test]
    fn parses_ipv4() {
        assert_eq!(
            p("/.well-known/masque/udp/192.0.2.6/443/"),
            Some(("192.0.2.6".into(), 443))
        );
    }

    #[test]
    fn parses_hostname() {
        assert_eq!(
            p("/.well-known/masque/udp/example.com/443/"),
            Some(("example.com".into(), 443))
        );
    }

    #[test]
    fn hostname_roundtrips_and_is_not_ip_literal() {
        // A hostname must survive encode → path → parse untouched, and must not
        // be misclassified as an IP literal — otherwise the server would connect
        // to it directly instead of resolving it via DNS.
        let encoded = encode_target_host("host1.example.com");
        let path = format!("{CONNECT_UDP_PATH}/{encoded}/7521/");
        let (host, port) = parse_connect_udp_path(&path).unwrap();
        assert_eq!((host.as_str(), port), ("host1.example.com", 7521));
        assert!(
            host.parse::<std::net::IpAddr>().is_err(),
            "hostname must NOT be treated as an IP literal"
        );
    }

    #[test]
    fn parses_percent_encoded_ipv6() {
        // RFC 9298 form: colons encoded as %3A, no brackets.
        // Address from the RFC 3849 documentation prefix (2001:db8::/32).
        assert_eq!(
            p("/.well-known/masque/udp/2001%3Adb8%3A101%3A1228%3A%3A4d23/29381/"),
            Some(("2001:db8:101:1228::4d23".into(), 29381))
        );
        assert_eq!(
            p("/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"),
            Some(("2001:db8::42".into(), 443))
        );
    }

    #[test]
    fn parses_bracketed_ipv6() {
        // Lenient: some clients send the bracketed literal unencoded.
        assert_eq!(
            p("/.well-known/masque/udp/[2001:db8:101:1228::4d23]/29381/"),
            Some(("2001:db8:101:1228::4d23".into(), 29381))
        );
    }

    #[test]
    fn decoded_ipv6_parses_as_ip() {
        let (host, _) =
            p("/.well-known/masque/udp/2001%3Adb8%3A101%3A1228%3A%3A4d23/29381/").unwrap();
        assert!(host.parse::<std::net::IpAddr>().is_ok());
    }

    #[test]
    fn encode_target_host_ipv6() {
        assert_eq!(
            encode_target_host("[2001:db8:101:1228::4d23]"),
            "2001%3Adb8%3A101%3A1228%3A%3A4d23"
        );
        assert_eq!(encode_target_host("192.0.2.6"), "192.0.2.6");
        assert_eq!(encode_target_host("example.com"), "example.com");
    }

    #[test]
    fn encode_decode_roundtrip_ipv6() {
        let host = "[2001:db8:101:1228::4d23]";
        let enc = encode_target_host(host);
        let path = format!("{CONNECT_UDP_PATH}/{enc}/29381/");
        assert_eq!(
            parse_connect_udp_path(&path),
            Some(("2001:db8:101:1228::4d23".into(), 29381))
        );
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(p("/.well-known/masque/udp/example.com/"), None);
    }

    #[test]
    fn parses_connect_ip_wildcards() {
        // RFC 9484 Errata ID 8444: the wildcard MUST arrive percent-encoded as
        // `%2A`; the server decodes it back to `*`.
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/%2A/%2A/"),
            Some(("*".into(), "*".into()))
        );
        // Tolerate a literal `*` too (pre-errata clients / lenient encoders).
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/*/*/"),
            Some(("*".into(), "*".into()))
        );
        // Trailing slash is optional in the wild.
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/%2A/%2A"),
            Some(("*".into(), "*".into()))
        );
    }

    #[test]
    fn rejects_connect_ip_bad_paths() {
        assert_eq!(parse_connect_ip_path("/.well-known/masque/ip/*/"), None);
        assert_eq!(parse_connect_ip_path("/.well-known/masque/ip/*/*/x/"), None);
        assert_eq!(parse_connect_ip_path("/.well-known/masque/udp/h/443/"), None);
    }

    #[test]
    fn datagram_ctx_roundtrip() {
        // Stream ID 8 → QSID 2; context 0; payload preserved.
        let wire = encode_datagram(8, b"pkt");
        let (sid, ctx, payload) = decode_datagram_ctx(&wire).unwrap();
        assert_eq!((sid, ctx, payload), (8, 0, b"pkt".as_slice()));
        // Non-zero context (keepalive) round-trips too.
        let ka = encode_datagram_ctx(8, 1, &[]);
        let (sid, ctx, payload) = decode_datagram_ctx(&ka).unwrap();
        assert_eq!((sid, ctx, payload), (8, 1, b"".as_slice()));
    }

    #[test]
    fn hop_limit_ipv4_decrements_and_fixes_checksum() {
        // Minimal IPv4 header, TTL 64, protocol UDP, valid checksum.
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[2] = 0x00;
        pkt[3] = 20; // total length
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 99, 0, 2]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        // Set a correct starting checksum.
        assert!(decrement_hop_limit(&mut pkt));
        assert_eq!(pkt[8], 63); // TTL decremented
        // Checksum must verify (one's-complement sum over the header == 0).
        let mut sum = 0u32;
        for c in pkt[..20].chunks_exact(2) {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff); // valid checksum sums to 0xffff before complement
    }

    #[test]
    fn hop_limit_drops_when_exhausted() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[8] = 1; // TTL 1 → would reach 0
        assert!(!decrement_hop_limit(&mut v4));

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[7] = 1; // Hop Limit 1 → would reach 0
        assert!(!decrement_hop_limit(&mut v6));
    }

    #[test]
    fn hop_limit_ipv6_decrements() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[7] = 64; // Hop Limit
        assert!(decrement_hop_limit(&mut pkt));
        assert_eq!(pkt[7], 63);
    }

    #[test]
    fn hop_limit_passes_through_non_ip() {
        let mut junk = vec![0xff, 0x00, 0x11];
        assert!(decrement_hop_limit(&mut junk)); // forwarded unchanged
        assert_eq!(junk, vec![0xff, 0x00, 0x11]);
    }
}
