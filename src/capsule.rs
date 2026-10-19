//! Capsule Protocol framing (RFC 9297) and CONNECT-IP capsules (RFC 9484).
//!
//! Capsules travel on the CONNECT-IP request stream as DATA payload:
//! `Type (varint) | Length (varint) | Value (..)`. Unknown capsule types
//! must be skipped without error (RFC 9297 §3.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::common::{decode_varint, put_varint};

/// ADDRESS_ASSIGN capsule type (RFC 9484 §4.7.1).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
/// ADDRESS_REQUEST capsule type (RFC 9484 §4.7.2).
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
/// ROUTE_ADVERTISEMENT capsule type (RFC 9484 §4.7.3).
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;
/// DNS_ASSIGN capsule type (draft-ietf-masque-connect-ip-dns). The draft's own
/// provisional codepoint; IANA assigns a smaller one when it becomes an RFC.
pub const CAPSULE_DNS_ASSIGN: u64 = 0x1ACE_79EC;

/// Upper bound on a single capsule's declared length. A hostile peer could
/// otherwise make us buffer indefinitely waiting for the capsule to complete.
pub const MAX_CAPSULE_SIZE: u64 = 1 << 20;

/// A complete capsule popped off the request stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    pub capsule_type: u64,
    pub payload: Bytes,
}

/// Incremental capsule parser. Capsules can be fragmented across DATA frames
/// (and DATA frames can contain several capsules), so bytes are accumulated
/// until at least one complete capsule is available.
#[derive(Default)]
pub struct CapsuleParser {
    buf: BytesMut,
}

impl CapsuleParser {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete capsule. `Ok(None)` means more bytes are needed;
    /// `Err` means the stream is malformed and must be aborted.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, &'static str> {
        let Some((capsule_type, type_len)) = decode_varint(&self.buf) else {
            return Ok(None);
        };
        let Some((len, len_len)) = decode_varint(&self.buf[type_len..]) else {
            return Ok(None);
        };
        if len > MAX_CAPSULE_SIZE {
            return Err("capsule exceeds size limit");
        }
        let total = type_len + len_len + len as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        self.buf.advance(type_len + len_len);
        let payload = self.buf.split_to(len as usize).freeze();
        Ok(Some(Capsule {
            capsule_type,
            payload,
        }))
    }
}

/// Assigned Address entry inside an ADDRESS_ASSIGN capsule (RFC 9484 §4.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    /// 0 when unprompted, otherwise echoes the ADDRESS_REQUEST Request ID.
    pub request_id: u64,
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// Requested Address entry inside an ADDRESS_REQUEST capsule (RFC 9484 §4.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAddress {
    /// Non-zero, unique per endpoint.
    pub request_id: u64,
    /// All-zero address means "no preference".
    pub addr: IpAddr,
    pub prefix_len: u8,
}

/// IP Address Range entry inside a ROUTE_ADVERTISEMENT capsule (RFC 9484 §4.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressRange {
    pub start: IpAddr,
    pub end: IpAddr,
    /// 0 allows all protocols, otherwise an IANA Internet Protocol Number.
    pub ip_proto: u8,
}

fn encode_capsule(capsule_type: u64, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(payload.len() + 16);
    put_varint(&mut buf, capsule_type);
    put_varint(&mut buf, payload.len() as u64);
    buf.put_slice(payload);
    buf.freeze()
}

fn put_versioned_addr(buf: &mut BytesMut, addr: &IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            buf.put_u8(4);
            buf.put_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.put_u8(6);
            buf.put_slice(&v6.octets());
        }
    }
}

/// Read a raw (version-less) address of the given IP version.
fn read_addr(version: u8, buf: &[u8]) -> Option<(IpAddr, usize)> {
    match version {
        4 => {
            let octets: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            Some((IpAddr::V4(Ipv4Addr::from(octets)), 4))
        }
        6 => {
            let octets: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            Some((IpAddr::V6(Ipv6Addr::from(octets)), 16))
        }
        _ => None,
    }
}

/// Shared layout of Assigned Address and Requested Address:
/// `Request ID (varint) | IP Version (8) | IP Address (32/128) | Prefix Length (8)`.
fn parse_address_entries(mut payload: &[u8]) -> Option<Vec<(u64, IpAddr, u8)>> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (request_id, n) = decode_varint(payload)?;
        payload = &payload[n..];
        let version = *payload.first()?;
        let (addr, n) = read_addr(version, &payload[1..])?;
        payload = &payload[1 + n..];
        let prefix_len = *payload.first()?;
        payload = &payload[1..];
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return None;
        }
        out.push((request_id, addr, prefix_len));
    }
    Some(out)
}

fn encode_address_entries(entries: impl Iterator<Item = (u64, IpAddr, u8)>) -> BytesMut {
    let mut buf = BytesMut::new();
    for (request_id, addr, prefix_len) in entries {
        put_varint(&mut buf, request_id);
        put_versioned_addr(&mut buf, &addr);
        buf.put_u8(prefix_len);
    }
    buf
}

/// Encode a complete ADDRESS_ASSIGN capsule (framing included).
pub fn encode_address_assign(addrs: &[AssignedAddress]) -> Bytes {
    let payload =
        encode_address_entries(addrs.iter().map(|a| (a.request_id, a.addr, a.prefix_len)));
    encode_capsule(CAPSULE_ADDRESS_ASSIGN, &payload)
}

/// Parse an ADDRESS_ASSIGN capsule payload.
pub fn parse_address_assign(payload: &[u8]) -> Option<Vec<AssignedAddress>> {
    Some(
        parse_address_entries(payload)?
            .into_iter()
            .map(|(request_id, addr, prefix_len)| AssignedAddress {
                request_id,
                addr,
                prefix_len,
            })
            .collect(),
    )
}

/// Encode a complete ADDRESS_REQUEST capsule (framing included).
pub fn encode_address_request(addrs: &[RequestedAddress]) -> Bytes {
    let payload =
        encode_address_entries(addrs.iter().map(|a| (a.request_id, a.addr, a.prefix_len)));
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &payload)
}

/// Parse an ADDRESS_REQUEST capsule payload. An empty list is malformed
/// (RFC 9484 §4.7.2) — the caller must abort the stream on `Some(vec![])`.
pub fn parse_address_request(payload: &[u8]) -> Option<Vec<RequestedAddress>> {
    Some(
        parse_address_entries(payload)?
            .into_iter()
            .map(|(request_id, addr, prefix_len)| RequestedAddress {
                request_id,
                addr,
                prefix_len,
            })
            .collect(),
    )
}

/// Encode a complete ROUTE_ADVERTISEMENT capsule (framing included).
/// Ranges must already satisfy the RFC 9484 §4.7.3 ordering requirements.
pub fn encode_route_advertisement(ranges: &[IpAddressRange]) -> Bytes {
    let mut payload = BytesMut::new();
    for range in ranges {
        match (&range.start, &range.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                payload.put_u8(4);
                payload.put_slice(&start.octets());
                payload.put_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                payload.put_u8(6);
                payload.put_slice(&start.octets());
                payload.put_slice(&end.octets());
            }
            _ => unreachable!("mixed-family IpAddressRange"),
        }
        payload.put_u8(range.ip_proto);
    }
    encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &payload)
}

/// Parse a ROUTE_ADVERTISEMENT capsule payload:
/// `IP Version (8) | Start (32/128) | End (32/128) | IP Protocol (8)` per range.
pub fn parse_route_advertisement(mut payload: &[u8]) -> Option<Vec<IpAddressRange>> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        let version = *payload.first()?;
        let (start, n) = read_addr(version, &payload[1..])?;
        let (end, m) = read_addr(version, &payload[1 + n..])?;
        let ip_proto = *payload.get(1 + n + m)?;
        payload = &payload[1 + n + m + 1..];
        if start > end {
            return None;
        }
        out.push(IpAddressRange {
            start,
            end,
            ip_proto,
        });
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// DNS_ASSIGN (draft-ietf-masque-connect-ip-dns-07). Minimal profile: plain Do53
// resolvers at IP addresses — no encrypted-DNS authentication domain, no SVCB
// service parameters, no search domains, and no split DNS: internal domains
// only tell a configuration that serves every name from a domain-scoped one.
//
// A capsule carries zero or more DNS Configurations (§3.4); an empty one
// withdraws any configuration sent before, and each DNS Configuration must
// carry at least one Nameserver (§3.3).
//
// DNS Configuration {
//   Nameserver Count (i), Nameserver (..) ...,
//   Internal Domain Count (i), Internal Domain (Domain) ...,
//   Search Domain Count (i), Search Domain (Domain) ...,
// }
// Nameserver {
//   Service Priority (16), IPv4 Address Count (i), IPv4 Address (32) ...,
//   IPv6 Address Count (i), IPv6 Address (128) ...,
//   Authentication Domain Name (Domain), Service Parameters Length (i)=0,
// }
// Domain { Domain Length (i), Domain Name (..) }
// ---------------------------------------------------------------------------

/// Encode a minimal DNS_ASSIGN capsule: one DNS Configuration with one
/// Nameserver entry per resolver address (Service Priority 1, empty auth
/// domain, no SvcParams => plain Do53), the DNS root as its only internal
/// domain (it serves every name, as in the draft's full-tunnel example), and no
/// search domains. No servers encodes the empty withdrawal capsule, since a DNS
/// Configuration with no Nameserver is invalid.
pub fn encode_dns_assign(servers: &[IpAddr]) -> Bytes {
    if servers.is_empty() {
        return encode_capsule(CAPSULE_DNS_ASSIGN, &[]);
    }
    let mut cfg = BytesMut::new();
    put_varint(&mut cfg, servers.len() as u64); // Nameserver Count
    for s in servers {
        cfg.put_u16(1); // Service Priority (SVCB); 1 = a normal entry
        match s {
            IpAddr::V4(a) => {
                put_varint(&mut cfg, 1);
                cfg.put_slice(&a.octets());
                put_varint(&mut cfg, 0);
            }
            IpAddr::V6(a) => {
                put_varint(&mut cfg, 0);
                put_varint(&mut cfg, 1);
                cfg.put_slice(&a.octets());
            }
        }
        put_varint(&mut cfg, 0); // Authentication Domain Name length (none)
        put_varint(&mut cfg, 0); // Service Parameters Length (plain Do53)
    }
    put_varint(&mut cfg, 1); // Internal Domain Count
    put_varint(&mut cfg, 0); // Internal Domain: "" (the DNS root)
    put_varint(&mut cfg, 0); // Search Domain Count
    encode_capsule(CAPSULE_DNS_ASSIGN, &cfg)
}

/// One DNS Configuration from a DNS_ASSIGN capsule, reduced to the minimal
/// profile: the plain-DNS resolver addresses of its Nameserver entries and
/// the internal domains they serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfiguration {
    pub servers: Vec<IpAddr>,
    pub internal_domains: Vec<String>,
}

impl DnsConfiguration {
    /// Whether the resolvers serve every name, so they can stand in for the
    /// system resolver: an internal domain of "" (the DNS root, §3.5), or "."
    /// as pre-07 drafts' presentation format wrote it, or no internal domains
    /// at all, as pre-07 senders (this crate's older servers included) encoded
    /// a full-tunnel configuration.
    pub fn is_global(&self) -> bool {
        self.internal_domains.is_empty()
            || self
                .internal_domains
                .iter()
                .any(|d| d.is_empty() || d == ".")
    }
}

/// The resolvers of the configurations that serve every name, in order and
/// without repeats. Domain-scoped configurations are left out: without split
/// DNS, installing them system-wide would send every query to resolvers only
/// known to serve some names.
pub fn global_resolvers(configs: &[DnsConfiguration]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for s in configs
        .iter()
        .filter(|c| c.is_global())
        .flat_map(|c| &c.servers)
    {
        if !out.contains(s) {
            out.push(*s);
        }
    }
    out
}

/// Parse a DNS_ASSIGN capsule payload into its DNS Configurations.
/// Authentication domains, SvcParams, and search domains are parsed past but
/// ignored (minimal profile). An empty payload is the withdrawal capsule and
/// yields no configurations.
pub fn parse_dns_assign(payload: &[u8]) -> Option<Vec<DnsConfiguration>> {
    let mut buf = payload;
    let mut out = Vec::new();
    while !buf.is_empty() {
        let (cfg, rest) = parse_dns_configuration(buf)?;
        out.push(cfg);
        buf = rest;
    }
    Some(out)
}

/// Parse one DNS Configuration off the front of `buf`, returning it and the
/// bytes after it.
fn parse_dns_configuration(mut buf: &[u8]) -> Option<(DnsConfiguration, &[u8])> {
    let (ns_count, n) = decode_varint(buf)?;
    if ns_count == 0 {
        return None; // Nameserver Count MUST NOT be zero (§3.3)
    }
    buf = &buf[n..];
    let mut servers = Vec::new();
    for _ in 0..ns_count {
        // Service Priority (16 bits) — unused in the minimal profile.
        if buf.len() < 2 {
            return None;
        }
        buf = &buf[2..];
        let (v4c, n) = decode_varint(buf)?;
        buf = &buf[n..];
        for _ in 0..v4c {
            let o: [u8; 4] = buf.get(..4)?.try_into().ok()?;
            servers.push(IpAddr::V4(Ipv4Addr::from(o)));
            buf = &buf[4..];
        }
        let (v6c, n) = decode_varint(buf)?;
        buf = &buf[n..];
        for _ in 0..v6c {
            let o: [u8; 16] = buf.get(..16)?.try_into().ok()?;
            servers.push(IpAddr::V6(Ipv6Addr::from(o)));
            buf = &buf[16..];
        }
        // Authentication Domain Name (Domain), then Service Parameters:
        // length-prefixed, both skipped.
        (_, buf) = take_prefixed(buf)?;
        (_, buf) = take_prefixed(buf)?;
    }
    let (internal_domains, rest) = parse_domains(buf)?;
    let (_search_domains, rest) = parse_domains(rest)?;
    Some((
        DnsConfiguration {
            servers,
            internal_domains,
        },
        rest,
    ))
}

/// Parse a count-prefixed list of Domain structures off the front of `buf`.
/// Names are ASCII (IDNA A-labels); anything else is replaced, not rejected.
fn parse_domains(mut buf: &[u8]) -> Option<(Vec<String>, &[u8])> {
    let (count, n) = decode_varint(buf)?;
    buf = &buf[n..];
    let mut out = Vec::new();
    for _ in 0..count {
        let (name, rest) = take_prefixed(buf)?;
        out.push(String::from_utf8_lossy(name).into_owned());
        buf = rest;
    }
    Some((out, buf))
}

/// Split a varint-length-prefixed field off the front of `buf`.
fn take_prefixed(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, n) = decode_varint(buf)?;
    let rest = &buf[n..];
    let len = usize::try_from(len).ok()?;
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(data: &[u8]) -> Vec<Capsule> {
        let mut parser = CapsuleParser::default();
        parser.push(data);
        let mut out = Vec::new();
        while let Some(c) = parser.next_capsule().unwrap() {
            out.push(c);
        }
        out
    }

    #[test]
    fn dns_assign_roundtrip() {
        let servers: Vec<IpAddr> = vec![
            "8.8.8.8".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
        ];
        let wire = encode_dns_assign(&servers);
        let capsules = parse_all(&wire);
        assert_eq!(capsules.len(), 1);
        assert_eq!(capsules[0].capsule_type, CAPSULE_DNS_ASSIGN);
        let configs = parse_dns_assign(&capsules[0].payload).unwrap();
        assert_eq!(
            configs,
            vec![DnsConfiguration {
                servers: servers.clone(),
                internal_domains: vec![String::new()],
            }]
        );
        assert_eq!(global_resolvers(&configs), servers);
    }

    #[test]
    fn dns_assign_empty_is_the_withdrawal_capsule() {
        let wire = encode_dns_assign(&[]);
        let capsules = parse_all(&wire);
        assert_eq!(capsules[0].capsule_type, CAPSULE_DNS_ASSIGN);
        assert!(capsules[0].payload.is_empty());
        assert_eq!(parse_dns_assign(&capsules[0].payload).unwrap(), vec![]);
    }

    #[test]
    fn dns_assign_rejects_zero_nameservers() {
        // Nameserver Count 0, Internal Domain Count 0, Search Domain Count 0:
        // what this crate sent for an empty set before draft -07 forbade it.
        assert_eq!(parse_dns_assign(&[0, 0, 0]), None);
    }

    /// One DNS Configuration with a single plain-DNS IPv4 nameserver.
    fn dns_configuration(server: [u8; 4], internal: &[&str], search: &[&str]) -> Vec<u8> {
        let mut b = BytesMut::new();
        put_varint(&mut b, 1); // Nameserver Count
        b.put_u16(1); // Service Priority
        put_varint(&mut b, 1);
        b.put_slice(&server);
        put_varint(&mut b, 0); // IPv6 Address Count
        put_varint(&mut b, 0); // Authentication Domain Name
        put_varint(&mut b, 0); // Service Parameters Length
        for list in [internal, search] {
            put_varint(&mut b, list.len() as u64);
            for d in list {
                put_varint(&mut b, d.len() as u64);
                b.put_slice(d.as_bytes());
            }
        }
        b.to_vec()
    }

    #[test]
    fn dns_assign_parses_every_configuration() {
        // The draft's split-tunnel example after a full-tunnel configuration.
        let mut payload = dns_configuration([8, 8, 8, 8], &[""], &[]);
        payload.extend(dns_configuration(
            [192, 0, 2, 33],
            &["internal.corp.example"],
            &["internal.corp.example", "corp.example"],
        ));
        let configs = parse_dns_assign(&payload).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[1].internal_domains, ["internal.corp.example"]);
        assert!(configs[0].is_global());
        assert!(!configs[1].is_global());
        // The domain-scoped resolver is not promoted to system-wide.
        assert_eq!(
            global_resolvers(&configs),
            ["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn dns_assign_only_scoped_configurations_yield_no_resolvers() {
        let payload = dns_configuration([192, 0, 2, 33], &["internal.corp.example"], &[]);
        let configs = parse_dns_assign(&payload).unwrap();
        assert!(global_resolvers(&configs).is_empty());
    }

    #[test]
    fn dns_assign_pre_07_root_encodings_are_global() {
        // No internal domains: what this crate's servers sent before -07.
        let none = parse_dns_assign(&dns_configuration([10, 0, 0, 1], &[], &[])).unwrap();
        assert!(none[0].is_global());
        // "." for the root, as pre-07 drafts' presentation format allowed.
        let dot = parse_dns_assign(&dns_configuration([10, 0, 0, 1], &["."], &[])).unwrap();
        assert!(dot[0].is_global());
    }

    #[test]
    fn dns_assign_resolvers_are_deduplicated_across_configurations() {
        let mut payload = dns_configuration([8, 8, 8, 8], &[""], &[]);
        payload.extend(dns_configuration([8, 8, 8, 8], &[], &[]));
        let configs = parse_dns_assign(&payload).unwrap();
        assert_eq!(
            global_resolvers(&configs),
            ["8.8.8.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn dns_assign_rejects_a_truncated_trailing_configuration() {
        let mut payload = dns_configuration([8, 8, 8, 8], &[""], &[]);
        let second = dns_configuration([1, 1, 1, 1], &[""], &[]);
        payload.extend(&second[..second.len() - 1]);
        assert_eq!(parse_dns_assign(&payload), None);
        // A Domain Length running past the end is malformed too.
        assert_eq!(parse_dns_assign(&[1, 0, 1, 0, 0, 0, 0, 1, 5, b'a']), None);
    }

    #[test]
    fn address_assign_roundtrip_v4() {
        let addrs = vec![AssignedAddress {
            request_id: 0,
            addr: "10.99.0.2".parse().unwrap(),
            prefix_len: 32,
        }];
        let wire = encode_address_assign(&addrs);
        let capsules = parse_all(&wire);
        assert_eq!(capsules.len(), 1);
        assert_eq!(capsules[0].capsule_type, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(parse_address_assign(&capsules[0].payload).unwrap(), addrs);
    }

    #[test]
    fn address_assign_roundtrip_v6() {
        let addrs = vec![
            AssignedAddress {
                request_id: 3,
                addr: "2001:db8::42".parse().unwrap(),
                prefix_len: 64,
            },
            AssignedAddress {
                request_id: 0,
                addr: "192.0.2.6".parse().unwrap(),
                prefix_len: 32,
            },
        ];
        let wire = encode_address_assign(&addrs);
        let capsules = parse_all(&wire);
        assert_eq!(parse_address_assign(&capsules[0].payload).unwrap(), addrs);
    }

    #[test]
    fn address_request_roundtrip() {
        let addrs = vec![RequestedAddress {
            request_id: 1,
            addr: "0.0.0.0".parse().unwrap(),
            prefix_len: 32,
        }];
        let wire = encode_address_request(&addrs);
        let capsules = parse_all(&wire);
        assert_eq!(capsules[0].capsule_type, CAPSULE_ADDRESS_REQUEST);
        assert_eq!(parse_address_request(&capsules[0].payload).unwrap(), addrs);
    }

    #[test]
    fn route_advertisement_roundtrip() {
        let ranges = vec![IpAddressRange {
            start: "0.0.0.0".parse().unwrap(),
            end: "255.255.255.255".parse().unwrap(),
            ip_proto: 0,
        }];
        let wire = encode_route_advertisement(&ranges);
        let capsules = parse_all(&wire);
        assert_eq!(capsules[0].capsule_type, CAPSULE_ROUTE_ADVERTISEMENT);
        assert_eq!(
            parse_route_advertisement(&capsules[0].payload).unwrap(),
            ranges
        );
    }

    #[test]
    fn route_advertisement_rejects_inverted_range() {
        let ranges = vec![IpAddressRange {
            start: "10.0.0.9".parse().unwrap(),
            end: "10.0.0.1".parse().unwrap(),
            ip_proto: 0,
        }];
        let wire = encode_route_advertisement(&ranges);
        let capsules = parse_all(&wire);
        assert_eq!(parse_route_advertisement(&capsules[0].payload), None);
    }

    #[test]
    fn parser_handles_fragmented_capsules() {
        let addrs = vec![AssignedAddress {
            request_id: 0,
            addr: "10.99.0.7".parse().unwrap(),
            prefix_len: 32,
        }];
        let wire = encode_address_assign(&addrs);
        let mut parser = CapsuleParser::default();
        // Feed one byte at a time; the capsule must pop out exactly once.
        let mut seen = Vec::new();
        for &b in wire.iter() {
            parser.push(&[b]);
            while let Some(c) = parser.next_capsule().unwrap() {
                seen.push(c);
            }
        }
        assert_eq!(seen.len(), 1);
        assert_eq!(parse_address_assign(&seen[0].payload).unwrap(), addrs);
    }

    #[test]
    fn parser_handles_multiple_capsules_in_one_push() {
        let a = encode_address_assign(&[AssignedAddress {
            request_id: 0,
            addr: "10.99.0.2".parse().unwrap(),
            prefix_len: 32,
        }]);
        let r = encode_route_advertisement(&[IpAddressRange {
            start: "0.0.0.0".parse().unwrap(),
            end: "255.255.255.255".parse().unwrap(),
            ip_proto: 0,
        }]);
        let mut joined = Vec::new();
        joined.extend_from_slice(&a);
        joined.extend_from_slice(&r);
        let capsules = parse_all(&joined);
        assert_eq!(capsules.len(), 2);
        assert_eq!(capsules[0].capsule_type, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(capsules[1].capsule_type, CAPSULE_ROUTE_ADVERTISEMENT);
    }

    #[test]
    fn parser_rejects_oversized_capsule() {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, 0x77);
        put_varint(&mut buf, MAX_CAPSULE_SIZE + 1);
        let mut parser = CapsuleParser::default();
        parser.push(&buf);
        assert!(parser.next_capsule().is_err());
    }

    #[test]
    fn unknown_capsule_type_is_surfaced_not_dropped() {
        // The parser only frames capsules; skipping unknown types is the
        // caller's job (RFC 9297 §3.2), so the type must round-trip as-is.
        let wire = encode_capsule(0x2b, b"opaque");
        let capsules = parse_all(&wire);
        assert_eq!(capsules[0].capsule_type, 0x2b);
        assert_eq!(&capsules[0].payload[..], b"opaque");
    }

    #[test]
    fn malformed_address_entry_returns_none() {
        // IP version 5 is invalid.
        assert_eq!(parse_address_assign(&[0x00, 0x05, 1, 2, 3, 4, 32]), None);
        // Prefix length beyond family maximum.
        assert_eq!(parse_address_assign(&[0x00, 0x04, 1, 2, 3, 4, 33]), None);
        // Truncated address.
        assert_eq!(parse_address_assign(&[0x00, 0x04, 1, 2]), None);
    }
}
