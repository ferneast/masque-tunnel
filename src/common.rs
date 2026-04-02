/// Well-known URI prefix for CONNECT-UDP (RFC 9298).
pub const CONNECT_UDP_PATH: &str = "/.well-known/masque/udp";

/// Encode a u64 as a QUIC variable-length integer (RFC 9000, Section 16).
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        ((value as u16) | 0x4000).to_be_bytes().to_vec()
    } else if value < 1_073_741_824 {
        ((value as u32) | 0x80000000).to_be_bytes().to_vec()
    } else {
        (value | 0xC000000000000000).to_be_bytes().to_vec()
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
pub fn encode_datagram(stream_id: u64, payload: &[u8]) -> Vec<u8> {
    let qsid = encode_varint(stream_id / 4);
    let mut buf = Vec::with_capacity(qsid.len() + 1 + payload.len());
    buf.extend_from_slice(&qsid);
    buf.push(0x00); // Context ID = 0
    buf.extend_from_slice(payload);
    buf
}

/// Decode a DATAGRAM payload. Returns (stream_id, udp_payload).
pub fn decode_datagram(buf: &[u8]) -> Option<(u64, &[u8])> {
    let (qsid, qsid_len) = decode_varint(buf)?;
    let stream_id = qsid * 4;
    let remaining = &buf[qsid_len..];
    let (_, ctx_len) = decode_varint(remaining)?;
    Some((stream_id, &remaining[ctx_len..]))
}

/// Parse a CONNECT-UDP path `/.well-known/masque/udp/{host}/{port}/` into (host, port).
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
    Some((host.to_string(), port))
}
