//! ICMP "Packet Too Big" generation for RFC 9484 §7.1.
//!
//! When a to-be-tunneled IP packet is larger than one HTTP Datagram can
//! carry, silently dropping it breaks Path MTU Discovery — the sender never
//! learns to send smaller packets, so connections stall on large transfers.
//! Instead we synthesize an ICMP error back to the packet's source:
//!   - IPv4: Destination Unreachable, code 4 (Fragmentation Needed, DF set)
//!   - IPv6: Packet Too Big
//!
//! The reply carries the tunnel's usable MTU so the source lowers its size.

/// RFC 1071 Internet checksum (one's-complement sum of 16-bit words).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an ICMP Packet-Too-Big for `original` (a full IP packet), advertising
/// `mtu` as the largest packet the tunnel can carry. Returns a complete IP
/// packet to write back toward the source, or `None` if `original` is not a
/// parseable IPv4/IPv6 packet.
pub fn packet_too_big(original: &[u8], mtu: u32) -> Option<Vec<u8>> {
    match original.first()? >> 4 {
        4 if original.len() >= 20 => Some(icmpv4_frag_needed(original, mtu as u16)),
        6 if original.len() >= 40 => Some(icmpv6_packet_too_big(original, mtu)),
        _ => None,
    }
}

/// ICMPv4 Destination Unreachable / Fragmentation Needed (type 3, code 4).
fn icmpv4_frag_needed(orig: &[u8], mtu: u16) -> Vec<u8> {
    let orig_src: [u8; 4] = orig[12..16].try_into().unwrap();
    let orig_dst: [u8; 4] = orig[16..20].try_into().unwrap();
    // RFC 792: quote the original IP header + first 8 bytes of payload.
    let quote_len = orig.len().min(28);

    // ICMP message: type, code, checksum, unused(2), next-hop MTU(2), quote.
    let mut icmp = Vec::with_capacity(8 + quote_len);
    icmp.extend_from_slice(&[3, 4, 0, 0, 0, 0]);
    icmp.extend_from_slice(&mtu.to_be_bytes());
    icmp.extend_from_slice(&orig[..quote_len]);
    let ck = checksum(&icmp);
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    // IPv4 header (20 bytes). Source it from the original destination so the
    // sender sees the error as coming from the far side of the path.
    let total_len = (20 + icmp.len()) as u16;
    let mut hdr = Vec::with_capacity(20);
    hdr.push(0x45); // version 4, IHL 5
    hdr.push(0); // DSCP/ECN
    hdr.extend_from_slice(&total_len.to_be_bytes());
    hdr.extend_from_slice(&[0, 0, 0, 0]); // id + flags/frag
    hdr.push(64); // TTL
    hdr.push(1); // protocol ICMP
    hdr.extend_from_slice(&[0, 0]); // header checksum placeholder
    hdr.extend_from_slice(&orig_dst); // src
    hdr.extend_from_slice(&orig_src); // dst
    let hck = checksum(&hdr);
    hdr[10..12].copy_from_slice(&hck.to_be_bytes());

    hdr.extend_from_slice(&icmp);
    hdr
}

/// ICMPv6 Packet Too Big (type 2, code 0), RFC 4443 §3.2.
fn icmpv6_packet_too_big(orig: &[u8], mtu: u32) -> Vec<u8> {
    let orig_src: [u8; 16] = orig[8..24].try_into().unwrap();
    let orig_dst: [u8; 16] = orig[24..40].try_into().unwrap();
    // Quote as much of the packet as fits without the ICMPv6 reply itself
    // exceeding the 1280 IPv6 minimum MTU: 1280 - 40 (IPv6) - 8 (ICMPv6) = 1232.
    let quote_len = orig.len().min(1232);
    let src = orig_dst; // reply source = original destination
    let dst = orig_src; // reply destination = original source

    // ICMPv6 message: type, code, checksum(2), MTU(4), quote.
    let mut icmp = Vec::with_capacity(8 + quote_len);
    icmp.extend_from_slice(&[2, 0, 0, 0]);
    icmp.extend_from_slice(&mtu.to_be_bytes());
    icmp.extend_from_slice(&orig[..quote_len]);

    // ICMPv6 checksum covers a pseudo-header (src, dst, upper-layer length,
    // next header = 58) followed by the ICMPv6 message.
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&icmp);
    let ck = checksum(&pseudo);
    icmp[2..4].copy_from_slice(&ck.to_be_bytes());

    // IPv6 header (40 bytes).
    let mut pkt = Vec::with_capacity(40 + icmp.len());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version 6, traffic class, flow label
    pkt.extend_from_slice(&(icmp.len() as u16).to_be_bytes()); // payload length
    pkt.push(58); // next header ICMPv6
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(&icmp);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A minimal IPv4 packet (header + `payload` bytes) with the given addrs.
    fn v4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload];
        p[0] = 0x45;
        let total = (20 + payload) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[9] = 6; // TCP, just to have a protocol
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn v6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: usize) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&(payload as u16).to_be_bytes());
        p[6] = 6; // next header TCP
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn v4_frag_needed_structure_and_checksums() {
        let orig = v4_packet("10.99.0.2".parse().unwrap(), "1.1.1.1".parse().unwrap(), 1400);
        let icmp = packet_too_big(&orig, 1300).unwrap();
        // IPv4 ICMP: version 4, protocol ICMP, addresses swapped.
        assert_eq!(icmp[0] >> 4, 4);
        assert_eq!(icmp[9], 1); // ICMP
        assert_eq!(&icmp[12..16], &[1, 1, 1, 1]); // src = original dst
        assert_eq!(&icmp[16..20], &[10, 99, 0, 2]); // dst = original src
        // ICMP type/code = 3/4, next-hop MTU = 1300.
        assert_eq!(icmp[20], 3);
        assert_eq!(icmp[21], 4);
        assert_eq!(u16::from_be_bytes([icmp[26], icmp[27]]), 1300);
        // Header checksum and ICMP checksum must verify to zero.
        assert_eq!(checksum(&icmp[..20]), 0);
        assert_eq!(checksum(&icmp[20..]), 0);
    }

    #[test]
    fn v6_packet_too_big_structure_and_checksum() {
        let orig = v6_packet("2001:db8::2".parse().unwrap(), "2606:4700::1".parse().unwrap(), 1400);
        let icmp = packet_too_big(&orig, 1300).unwrap();
        assert_eq!(icmp[0] >> 4, 6);
        assert_eq!(icmp[6], 58); // next header ICMPv6
        assert_eq!(&icmp[8..24], &"2606:4700::1".parse::<Ipv6Addr>().unwrap().octets()); // src = orig dst
        assert_eq!(&icmp[24..40], &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets()); // dst = orig src
        assert_eq!(icmp[40], 2); // Packet Too Big
        assert_eq!(icmp[41], 0);
        assert_eq!(u32::from_be_bytes([icmp[44], icmp[45], icmp[46], icmp[47]]), 1300);
        // The whole reply must not exceed the IPv6 minimum MTU.
        assert!(icmp.len() <= 1280);
        // Verify the ICMPv6 checksum over the pseudo-header + message.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&icmp[8..24]); // src
        pseudo.extend_from_slice(&icmp[24..40]); // dst
        pseudo.extend_from_slice(&((icmp.len() - 40) as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&icmp[40..]);
        assert_eq!(checksum(&pseudo), 0);
    }

    #[test]
    fn ignores_non_ip() {
        assert!(packet_too_big(&[0x00, 0x01, 0x02], 1300).is_none());
        assert!(packet_too_big(&[], 1300).is_none());
    }
}
