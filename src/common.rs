use bytes::{BufMut, BytesMut};

/// Well-known URI prefix for CONNECT-UDP (RFC 9298).
pub const CONNECT_UDP_PATH: &str = "/.well-known/masque/udp";

/// Well-known URI prefix for CONNECT-IP (RFC 9484).
pub const CONNECT_IP_PATH: &str = "/.well-known/masque/ip";

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

/// Prepend the RFC 9298/9484 context ID to a datagram body. tokio-quiche adds
/// the RFC 9297 quarter-stream-id itself, so the body we hand it is just
/// `Context ID (varint) | Payload`. Context ID 0 carries the proxied payload.
pub fn encode_context_payload(context_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(8 + payload.len());
    put_varint(&mut buf, context_id);
    buf.put_slice(payload);
    buf.to_vec()
}

/// Split a received datagram body into (context_id, payload).
///
/// Both RFC 9298 and RFC 9484 reserve Context ID 0 for the actual proxied
/// payload; callers must drop datagrams with any other context ID instead of
/// forwarding them.
pub fn decode_context_payload(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (context_id, n) = decode_varint(buf)?;
    Some((context_id, &buf[n..]))
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

    fn p(path: &str) -> Option<(String, u16)> {
        parse_connect_udp_path(path)
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
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/*/*/"),
            Some(("*".into(), "*".into()))
        );
        // Trailing slash is optional in the wild.
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/*/*"),
            Some(("*".into(), "*".into()))
        );
    }

    #[test]
    fn parses_connect_ip_scoped_target() {
        assert_eq!(
            parse_connect_ip_path("/.well-known/masque/ip/2001%3Adb8%3A%3A42%2F64/17/"),
            Some(("2001:db8::42/64".into(), "17".into()))
        );
    }

    #[test]
    fn rejects_connect_ip_bad_paths() {
        assert_eq!(parse_connect_ip_path("/.well-known/masque/ip/*/"), None);
        assert_eq!(parse_connect_ip_path("/.well-known/masque/ip/*/*/x/"), None);
        assert_eq!(parse_connect_ip_path("/.well-known/masque/udp/h/443/"), None);
    }

    #[test]
    fn context_payload_roundtrip() {
        let body = encode_context_payload(0, b"hello");
        assert_eq!(body, vec![0x00, b'h', b'e', b'l', b'l', b'o']);
        let (ctx, payload) = decode_context_payload(&body).unwrap();
        assert_eq!(ctx, 0);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn context_payload_drops_nonzero_context() {
        // Context ID 1 encodes as a single varint byte 0x01.
        let (ctx, payload) = decode_context_payload(&[0x01, 0xaa, 0xbb]).unwrap();
        assert_eq!(ctx, 1);
        assert_eq!(payload, &[0xaa, 0xbb]);
    }
}
