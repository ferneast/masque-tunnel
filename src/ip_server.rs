//! Server-side CONNECT-IP support (RFC 9484) on the quinn / h3 stack.
//!
//! One shared TUN device serves every CONNECT-IP session. Each session is
//! assigned a /32 from a configured IPv4 pool and/or a /128 from an IPv6
//! pool (dual-stack); downstream packets read from the TUN are routed to
//! sessions by destination address and sent as QUIC DATAGRAMs on the owning
//! connection, upstream packets are source-validated and written to the TUN.
//! Capsules travel on the request stream body; IP packets travel in HTTP
//! Datagrams with an RFC 9484 context ID of 0. Forwarding between the TUN
//! and the internet is the kernel's job (IP forwarding + NAT), which also
//! handles the RFC 9484 §7.1 TTL decrement for transited packets.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, RwLock};

use bytes::{Buf, Bytes};
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

use crate::capsule::*;
use crate::common::*;

/// The full bidirectional request stream of a CONNECT-IP request.
pub type H3RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type H3SendHalf = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type H3RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// CONNECT-IP server configuration (present only when a pool is given).
pub struct IpConfig {
    /// IPv4 pool in CIDR notation, e.g. `10.99.0.0/24`. The first host
    /// address is taken by the TUN device; clients get one `/32` each.
    pub pool_v4: Option<String>,
    /// IPv6 pool in CIDR notation, e.g. `2001:db8:1::/64`. The first host
    /// address is taken by the TUN device; clients get one `/128` each.
    pub pool_v6: Option<String>,
    /// MTU of the TUN device; bounds the size of tunneled packets.
    pub mtu: u16,
    /// Optional TUN device name (Linux: any; macOS: `utunN`).
    pub tun_name: Option<String>,
    /// Routes to advertise to clients via ROUTE_ADVERTISEMENT, as CIDRs.
    /// Empty means advertise a full tunnel (0.0.0.0/0 and/or ::/0 for each
    /// assigned family). Loaded once at startup (see `parse_routes_file`).
    pub advertised_routes: Vec<(IpAddr, u8)>,
}

/// Allocates client host addresses from a v4 or v6 pool, skipping the
/// network address, the server address (network+1), and — for IPv4 — the
/// broadcast address. Addresses are handed out sequentially; for privacy in
/// public deployments a randomized scheme would be preferable (RFC 9484
/// §8.2), but sequential keeps allocation deterministic and testable.
struct AddressPool {
    /// Pool network address, IPv4 mapped into the low 32 bits of a u128.
    network: u128,
    /// Number of host bits in the prefix (32 - prefix for v4, 128 for v6).
    host_bits: u32,
    is_v6: bool,
    in_use: HashSet<u128>,
}

impl AddressPool {
    fn new(network: IpAddr, prefix: u8) -> Self {
        match network {
            IpAddr::V4(v4) => Self {
                network: u32::from(v4) as u128,
                host_bits: 32 - prefix as u32,
                is_v6: false,
                in_use: HashSet::new(),
            },
            IpAddr::V6(v6) => Self {
                network: u128::from(v6),
                host_bits: 128 - prefix as u32,
                is_v6: true,
                in_use: HashSet::new(),
            },
        }
    }

    fn to_ip(&self, v: u128) -> IpAddr {
        if self.is_v6 {
            IpAddr::V6(Ipv6Addr::from(v))
        } else {
            IpAddr::V4(Ipv4Addr::from(v as u32))
        }
    }

    fn alloc(&mut self) -> Option<IpAddr> {
        let span = 1u128.checked_shl(self.host_bits)?; // addresses in the prefix
        let first = self.network.saturating_add(2); // skip network + server
        // IPv4 reserves the broadcast (last) address; IPv6 has no broadcast.
        let broadcast_reserve = if self.is_v6 { 0 } else { 1 };
        let last = self
            .network
            .saturating_add(span)
            .saturating_sub(1 + broadcast_reserve);
        if first > last {
            return None;
        }
        (first..=last)
            .find(|a| self.in_use.insert(*a))
            .map(|a| self.to_ip(a))
    }

    fn free(&mut self, ip: IpAddr) {
        let v = match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
        self.in_use.remove(&v);
    }
}

/// Downstream target for one assigned client address: the owning QUIC
/// connection and the CONNECT-IP request's stream ID (for the quarter
/// stream ID in each datagram). quinn::Connection clones are cheap and
/// send_datagram is internally synchronized.
#[derive(Clone)]
struct DownstreamFlow {
    conn: quinn::Connection,
    stream_id: u64,
}

/// Shared CONNECT-IP state. Global across QUIC connections: the TUN device
/// is one per process, so the routing table must span all connections.
pub struct IpTunState {
    tun: Arc<AsyncDevice>,
    pool_v4: Option<Mutex<AddressPool>>,
    pool_v6: Option<Mutex<AddressPool>>,
    routes: RwLock<HashMap<IpAddr, DownstreamFlow>>,
    /// Routes advertised via ROUTE_ADVERTISEMENT (CIDRs). Empty = full tunnel.
    advertised_routes: Vec<(IpAddr, u8)>,
}

impl IpTunState {
    /// Allocate one address from the matching family's pool.
    fn alloc(&self, want_v6: bool) -> Option<IpAddr> {
        let pool = if want_v6 { &self.pool_v6 } else { &self.pool_v4 };
        pool.as_ref().and_then(|p| p.lock().unwrap().alloc())
    }

    /// Return an address to the pool it came from.
    fn free(&self, ip: IpAddr) {
        let pool = if ip.is_ipv6() { &self.pool_v6 } else { &self.pool_v4 };
        if let Some(p) = pool {
            p.lock().unwrap().free(ip);
        }
    }
}

/// Highest prefix length (single host) for an address's family.
fn max_prefix(ip: IpAddr) -> u8 {
    if ip.is_ipv6() {
        128
    } else {
        32
    }
}

/// The all-zero address of the same family (used to refuse a request).
fn unspecified_like(ip_is_v6: bool) -> IpAddr {
    if ip_is_v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

/// The nth host address in a pool (network + n).
fn nth_host(network: IpAddr, n: u128) -> IpAddr {
    match network {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from((u32::from(v4) as u128 + n) as u32)),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) + n)),
    }
}

/// Parse `addr/len` CIDR notation for either family, requiring the given one.
fn parse_cidr(s: &str, want_v6: bool) -> Result<(IpAddr, u8), String> {
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR (expected addr/len): {s}"))?;
    let len: u8 = len.parse().map_err(|e| format!("invalid prefix length: {e}"))?;

    if !want_v6 {
        let v4: Ipv4Addr = addr
            .parse()
            .map_err(|e| format!("invalid IPv4 pool address {addr}: {e}"))?;
        if len > 30 {
            return Err("IPv4 pool prefix must be /30 or larger (needs a client address)".into());
        }
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        if u32::from(v4) & !mask != 0 {
            return Err(format!("pool {s} has host bits set"));
        }
        Ok((IpAddr::V4(v4), len))
    } else {
        let v6: Ipv6Addr = addr
            .parse()
            .map_err(|e| format!("invalid IPv6 pool address {addr}: {e}"))?;
        if !(1..=126).contains(&len) {
            return Err("IPv6 pool prefix must be between /1 and /126".into());
        }
        let mask = u128::MAX << (128 - len);
        if u128::from(v6) & !mask != 0 {
            return Err(format!("pool {s} has host bits set"));
        }
        Ok((IpAddr::V6(v6), len))
    }
}

/// Load the `--ip-routes-file`: one CIDR per line, with `#` comments and blank
/// lines ignored. Host bits are tolerated (masked off when converted to a
/// range). Fails fast on a malformed line so a bad config never silently
/// advertises the wrong tunnel.
pub fn parse_routes_file(
    path: &str,
) -> Result<Vec<(IpAddr, u8)>, Box<dyn std::error::Error + Send + Sync>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read --ip-routes-file {path}: {e}"))?;
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        // Strip trailing/inline comments and surrounding whitespace.
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let ln = i + 1;
        let (addr, len) = line
            .split_once('/')
            .ok_or_else(|| format!("{path}:{ln}: not a CIDR (expected addr/len): {line}"))?;
        let net: IpAddr = addr
            .trim()
            .parse()
            .map_err(|e| format!("{path}:{ln}: invalid address {addr}: {e}"))?;
        let prefix: u8 = len
            .trim()
            .parse()
            .map_err(|e| format!("{path}:{ln}: invalid prefix {len}: {e}"))?;
        let max = if net.is_ipv6() { 128 } else { 32 };
        if prefix > max {
            return Err(format!("{path}:{ln}: prefix /{prefix} exceeds /{max}").into());
        }
        out.push((net, prefix));
    }
    Ok(out)
}

/// Convert a CIDR (network/prefix, host bits ignored) to the inclusive
/// [start, end] IpAddressRange the ROUTE_ADVERTISEMENT capsule carries, for all
/// protocols (ip_proto 0).
fn cidr_to_range(net: IpAddr, prefix: u8) -> IpAddressRange {
    match net {
        IpAddr::V4(v4) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let base = u32::from(v4) & mask;
            IpAddressRange {
                start: IpAddr::V4(Ipv4Addr::from(base)),
                end: IpAddr::V4(Ipv4Addr::from(base | !mask)),
                ip_proto: 0,
            }
        }
        IpAddr::V6(v6) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            let base = u128::from(v6) & mask;
            IpAddressRange {
                start: IpAddr::V6(Ipv6Addr::from(base)),
                end: IpAddr::V6(Ipv6Addr::from(base | !mask)),
                ip_proto: 0,
            }
        }
    }
}

/// Build the ROUTE_ADVERTISEMENT range set for a session (RFC 9484 §4.7.3:
/// each advertisement carries the complete route set, ordered ascending with
/// IPv4 before IPv6). With no configured routes this advertises a full tunnel
/// per assigned family; otherwise it advertises the configured CIDRs, but only
/// for families the client actually holds an address in (a route it cannot
/// source is useless).
fn route_ranges(advertised: &[(IpAddr, u8)], assigned: &[(IpAddr, u8)]) -> Vec<IpAddressRange> {
    let has_v4 = assigned.iter().any(|(ip, _)| ip.is_ipv4());
    let has_v6 = assigned.iter().any(|(ip, _)| ip.is_ipv6());

    if advertised.is_empty() {
        let mut ranges = Vec::new();
        if has_v4 {
            ranges.push(IpAddressRange {
                start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                end: IpAddr::V4(Ipv4Addr::BROADCAST),
                ip_proto: 0,
            });
        }
        if has_v6 {
            ranges.push(IpAddressRange {
                start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: IpAddr::V6(Ipv6Addr::from(u128::MAX)),
                ip_proto: 0,
            });
        }
        return ranges;
    }

    let mut v4: Vec<IpAddressRange> = Vec::new();
    let mut v6: Vec<IpAddressRange> = Vec::new();
    for (net, prefix) in advertised {
        match net {
            IpAddr::V4(_) if has_v4 => v4.push(cidr_to_range(*net, *prefix)),
            IpAddr::V6(_) if has_v6 => v6.push(cidr_to_range(*net, *prefix)),
            _ => {} // client has no address in this family; the route is useless
        }
    }
    v4.sort_by_key(|r| r.start);
    v6.sort_by_key(|r| r.start);
    v4.into_iter().chain(v6).collect()
}

/// Source address of an IP packet (v4 or v6), or `None` if malformed.
fn packet_src(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => {
            let o: [u8; 4] = pkt[12..16].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        }
        6 if pkt.len() >= 40 => {
            let o: [u8; 16] = pkt[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Destination address of an IP packet (v4 or v6), or `None` if malformed.
fn packet_dst(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => {
            let o: [u8; 4] = pkt[16..20].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        }
        6 if pkt.len() >= 40 => {
            let o: [u8; 16] = pkt[24..40].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Create the TUN device and spawn the downstream (TUN -> clients) router.
pub fn init(config: &IpConfig) -> Result<Arc<IpTunState>, Box<dyn std::error::Error + Send + Sync>> {
    let v4 = config
        .pool_v4
        .as_deref()
        .map(|s| parse_cidr(s, false))
        .transpose()?;
    let v6 = config
        .pool_v6
        .as_deref()
        .map(|s| parse_cidr(s, true))
        .transpose()?;
    if v4.is_none() && v6.is_none() {
        return Err("CONNECT-IP requires at least one address pool".into());
    }
    if v6.is_some() && config.mtu < 1280 {
        log::warn!(
            "[server] CONNECT-IP MTU {} is below the IPv6 minimum of 1280; IPv6 may break",
            config.mtu
        );
    }

    let mut builder = tun_rs::DeviceBuilder::new().mtu(config.mtu);
    let mut desc = Vec::new();
    if let Some((net, prefix)) = &v4 {
        let IpAddr::V4(server_ip) = nth_host(*net, 1) else {
            unreachable!()
        };
        builder = builder.ipv4(server_ip, *prefix, None);
        desc.push(format!("v4={server_ip}/{prefix}"));
    }
    if let Some((net, prefix)) = &v6 {
        let IpAddr::V6(server_ip) = nth_host(*net, 1) else {
            unreachable!()
        };
        builder = builder.ipv6(server_ip, *prefix);
        desc.push(format!("v6={server_ip}/{prefix}"));
    }
    if let Some(name) = &config.tun_name {
        builder = builder.name(name);
    }
    let tun = Arc::new(builder.build_async()?);
    let tun_name = tun.name().unwrap_or_else(|_| "?".into());
    log::info!(
        "[server] CONNECT-IP enabled: tun={tun_name} {} mtu={}",
        desc.join(" "),
        config.mtu
    );

    let state = Arc::new(IpTunState {
        tun,
        pool_v4: v4.map(|(net, prefix)| Mutex::new(AddressPool::new(net, prefix))),
        pool_v6: v6.map(|(net, prefix)| Mutex::new(AddressPool::new(net, prefix))),
        routes: RwLock::new(HashMap::new()),
        advertised_routes: config.advertised_routes.clone(),
    });
    if !state.advertised_routes.is_empty() {
        log::info!(
            "[server] CONNECT-IP advertising {} configured route(s) (split tunnel)",
            state.advertised_routes.len()
        );
    }

    // Downstream router: TUN -> a QUIC DATAGRAM on the connection of the
    // session that owns the destination address.
    let st = state.clone();
    let mtu = config.mtu;
    tokio::spawn(async move {
        let mut buf = vec![0u8; mtu as usize + 64];
        loop {
            match st.tun.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = &buf[..n];
                    // Oversized for one datagram: reply ICMP Packet Too Big to
                    // the source (RFC 9484 §7.1) instead of dropping silently.
                    if n as u32 > TUNNEL_IP_MTU {
                        if let Some(icmp) = crate::icmp::packet_too_big(pkt, TUNNEL_IP_MTU) {
                            let _ = st.tun.try_send(&icmp);
                        }
                        continue;
                    }
                    let Some(dst) = packet_dst(pkt) else { continue };
                    let flow = { st.routes.read().unwrap().get(&dst).cloned() };
                    let Some(flow) = flow else { continue };
                    let dgram = encode_datagram(flow.stream_id, pkt);
                    let overhead = dgram.len() - n;
                    match flow.conn.send_datagram(dgram) {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => {
                            // The path MTU is below TUNNEL_IP_MTU right now;
                            // tell the source the currently usable size.
                            let usable = flow
                                .conn
                                .max_datagram_size()
                                .map(|m| m.saturating_sub(overhead))
                                .unwrap_or(0);
                            if usable >= 576 {
                                if let Some(icmp) =
                                    crate::icmp::packet_too_big(pkt, usable as u32)
                                {
                                    let _ = st.tun.try_send(&icmp);
                                }
                            }
                        }
                        Err(_) => {} // connection gone; session cleanup removes the route
                    }
                }
                Err(e) => {
                    log::error!("[server] TUN recv error: {e}");
                    break;
                }
            }
        }
    });

    Ok(state)
}

/// Cleans up a session's routes and pool allocations when dropped.
struct IpSessionGuard {
    assigned: Vec<IpAddr>,
    state: Arc<IpTunState>,
}

impl Drop for IpSessionGuard {
    fn drop(&mut self) {
        {
            let mut routes = self.state.routes.write().unwrap();
            for ip in &self.assigned {
                routes.remove(ip);
            }
        }
        for ip in &self.assigned {
            self.state.free(*ip);
        }
        log::info!("[server] CONNECT-IP session released: {:?}", self.assigned);
    }
}

/// Per-connection handle for one established CONNECT-IP session, stored in
/// the connection's session map for upstream datagram dispatch. Dropping it
/// aborts the capsule task, whose guard frees routes and pool addresses.
pub struct IpSession {
    tun: Arc<AsyncDevice>,
    assigned: Vec<IpAddr>,
    capsule: tokio::task::AbortHandle,
}

impl IpSession {
    /// Upstream: HTTP Datagram payload -> TUN, with anti-spoofing source
    /// validation. Context IDs other than 0 are reserved and dropped.
    pub fn forward_upstream(&self, context_id: u64, pkt: &[u8]) {
        if context_id != 0 {
            return;
        }
        match packet_src(pkt) {
            // try_send: never block; a full TUN queue drops, which IP tolerates.
            Some(src) if self.assigned.contains(&src) => {
                let _ = self.tun.try_send(pkt);
            }
            _ => log::trace!(
                "[server] drop packet with invalid source (assigned {:?})",
                self.assigned
            ),
        }
    }
}

impl Drop for IpSession {
    fn drop(&mut self) {
        self.capsule.abort();
    }
}

async fn reply_error(stream: &mut H3RequestStream, status: u16) {
    let resp = http::Response::builder().status(status).body(()).unwrap();
    let _ = stream.send_response(resp).await;
    let _ = stream.finish().await;
}

/// Handle a CONNECT-IP extended CONNECT request that has already been
/// authenticated. On success returns the raw QUIC stream ID and the session
/// handle to register for datagram dispatch; on failure an error status has
/// already been sent.
pub async fn handle_ip_request(
    state: &Arc<IpTunState>,
    path: &str,
    mut stream: H3RequestStream,
    conn: &quinn::Connection,
    cleanup_tx: &mpsc::Sender<u64>,
) -> Option<(u64, IpSession)> {
    let Some((target, ipproto)) = parse_connect_ip_path(path) else {
        log::info!("[server] Invalid CONNECT-IP path: {path}");
        reply_error(&mut stream, 400).await;
        return None;
    };

    // Only full-tunnel requests are supported. Scoped targets/protocols would
    // require per-session packet filtering; RFC 9484 §4.1 lets proxies reject
    // requests outside their configured scope.
    if target != "*" || ipproto != "*" {
        log::info!("[server] Rejecting scoped CONNECT-IP request: target={target} ipproto={ipproto}");
        reply_error(&mut stream, 403).await;
        return None;
    }

    // Assign one address per configured family.
    let mut assigned: Vec<(IpAddr, u8)> = Vec::new();
    if let Some(ip) = state.alloc(false) {
        assigned.push((ip, 32));
    }
    if let Some(ip) = state.alloc(true) {
        assigned.push((ip, 128));
    }
    if assigned.is_empty() {
        log::warn!("[server] CONNECT-IP address pool exhausted");
        reply_error(&mut stream, 503).await;
        return None;
    }
    let free_all = |state: &Arc<IpTunState>| {
        for (ip, _) in &assigned {
            state.free(*ip);
        }
    };

    // 200 response, then the unprompted ADDRESS_ASSIGN (complete set) and a
    // default route per family (RFC 9484 §4.7.1/§4.7.3) as capsule bodies.
    let resp = http::Response::builder()
        .status(200)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    if let Err(e) = stream.send_response(resp).await {
        log::error!("[server] Failed to send CONNECT-IP 200: {e}");
        free_all(state);
        return None;
    }

    let assign = encode_address_assign(
        &assigned
            .iter()
            .map(|(ip, pfx)| AssignedAddress {
                request_id: 0,
                addr: *ip,
                prefix_len: *pfx,
            })
            .collect::<Vec<_>>(),
    );
    let ranges = route_ranges(&state.advertised_routes, &assigned);
    let route_caps = encode_route_advertisement(&ranges);
    if stream.send_data(assign).await.is_err() || stream.send_data(route_caps).await.is_err() {
        log::error!("[server] Failed to send CONNECT-IP capsules");
        free_all(state);
        return None;
    }

    // h3's StreamId::index() is the stream's ordinal (raw QUIC stream ID / 4
    // for client-initiated bidi), which is exactly the RFC 9297 quarter
    // stream ID; the raw QUIC stream ID is index * 4.
    let h3_index = stream.send_id().index();
    let quic_stream_id = h3_index * 4;
    let assigned_ips: Vec<IpAddr> = assigned.iter().map(|(ip, _)| *ip).collect();
    log::info!(
        "[server] CONNECT-IP established: stream_id={quic_stream_id} assigned={assigned_ips:?}"
    );

    {
        let mut routes = state.routes.write().unwrap();
        for ip in &assigned_ips {
            routes.insert(
                *ip,
                DownstreamFlow {
                    conn: conn.clone(),
                    stream_id: quic_stream_id,
                },
            );
        }
    }

    // Capsule task: reads capsules off the request stream until FIN/reset,
    // then the guard drops (cleaning routes + pool) and the session entry is
    // removed from the connection's map via cleanup_tx.
    let guard = IpSessionGuard {
        assigned: assigned_ips.clone(),
        state: state.clone(),
    };
    let (send_half, recv_half) = stream.split();
    let cleanup = cleanup_tx.clone();
    let capsule_assigned = assigned_ips.clone();
    let handle = tokio::spawn(async move {
        let _guard = guard;
        capsule_loop(recv_half, send_half, capsule_assigned).await;
        let _ = cleanup.send(quic_stream_id).await;
    });

    Some((
        quic_stream_id,
        IpSession {
            tun: state.tun.clone(),
            assigned: assigned_ips,
            capsule: handle.abort_handle(),
        },
    ))
}

/// Capsule loop: reads capsules off the request-stream body and answers
/// ADDRESS_REQUESTs. Ends on FIN/reset, which tears the session down.
async fn capsule_loop(mut recv: H3RecvHalf, mut send: H3SendHalf, assigned: Vec<IpAddr>) {
    let mut parser = CapsuleParser::default();
    loop {
        match recv.recv_data().await {
            Ok(Some(mut buf)) => {
                while buf.has_remaining() {
                    let chunk = buf.chunk();
                    parser.push(chunk);
                    let n = chunk.len();
                    buf.advance(n);
                }
                loop {
                    match parser.next_capsule() {
                        Ok(Some(capsule)) => handle_capsule(&mut send, capsule, &assigned).await,
                        Ok(None) => break,
                        Err(e) => {
                            log::warn!("[server] Malformed capsule from {assigned:?}: {e}");
                            return;
                        }
                    }
                }
            }
            Ok(None) => break, // FIN: client ended the session
            Err(e) => {
                log::debug!("[server] CONNECT-IP stream ended: {e}");
                break;
            }
        }
    }
}

async fn handle_capsule(send: &mut H3SendHalf, capsule: Capsule, assigned: &[IpAddr]) {
    match capsule.capsule_type {
        CAPSULE_ADDRESS_REQUEST => {
            let Some(requests) = parse_address_request(&capsule.payload) else {
                log::warn!("[server] Malformed ADDRESS_REQUEST from {assigned:?}");
                return;
            };
            if requests.is_empty() {
                log::warn!("[server] Empty ADDRESS_REQUEST from {assigned:?}");
                return;
            }
            // Answer each request with the already-assigned address of the
            // matching family for a no-preference (or exact-match) request,
            // and refuse anything else with the all-zero address + max prefix
            // length (RFC 9484 §4.7.1). ADDRESS_ASSIGN must carry the complete
            // assigned set, so any address not claimed by a request is appended
            // with Request ID 0.
            let mut out = Vec::new();
            let mut claimed: Vec<IpAddr> = Vec::new();
            for r in &requests {
                let want_v6 = r.addr.is_ipv6();
                let no_pref = r.addr.is_unspecified();
                let matched = assigned.iter().copied().find(|a| {
                    a.is_ipv6() == want_v6 && (no_pref || *a == r.addr) && !claimed.contains(a)
                });
                if let Some(a) = matched {
                    claimed.push(a);
                    out.push(AssignedAddress {
                        request_id: r.request_id,
                        addr: a,
                        prefix_len: max_prefix(a),
                    });
                } else {
                    out.push(AssignedAddress {
                        request_id: r.request_id,
                        addr: unspecified_like(want_v6),
                        prefix_len: if want_v6 { 128 } else { 32 },
                    });
                }
            }
            for a in assigned {
                if !claimed.contains(a) {
                    out.push(AssignedAddress {
                        request_id: 0,
                        addr: *a,
                        prefix_len: max_prefix(*a),
                    });
                }
            }
            let _ = send.send_data(encode_address_assign(&out)).await;
        }
        CAPSULE_ROUTE_ADVERTISEMENT => {
            // We never route traffic toward client networks (full-tunnel NAT
            // deployment), so client routes are noted and ignored.
            match parse_route_advertisement(&capsule.payload) {
                Some(ranges) => log::debug!(
                    "[server] Ignoring ROUTE_ADVERTISEMENT from {assigned:?}: {} range(s)",
                    ranges.len()
                ),
                None => log::warn!("[server] Malformed ROUTE_ADVERTISEMENT from {assigned:?}"),
            }
        }
        CAPSULE_ADDRESS_ASSIGN => {
            log::debug!("[server] Ignoring ADDRESS_ASSIGN from client {assigned:?}");
        }
        // Unknown capsule types must be ignored (RFC 9297 §3.2).
        other => log::trace!("[server] Ignoring unknown capsule type {other:#x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parses_v4() {
        assert_eq!(
            parse_cidr("10.99.0.0/24", false).unwrap(),
            ("10.99.0.0".parse().unwrap(), 24)
        );
        assert!(parse_cidr("10.99.0.1/24", false).is_err()); // host bits set
        assert!(parse_cidr("10.99.0.0/31", false).is_err()); // too small
        assert!(parse_cidr("10.99.0.0", false).is_err());
        assert!(parse_cidr("2001:db8::/64", false).is_err()); // v6 where v4 wanted
    }

    #[test]
    fn cidr_parses_v6() {
        assert_eq!(
            parse_cidr("2001:db8:1::/64", true).unwrap(),
            ("2001:db8:1::".parse().unwrap(), 64)
        );
        assert!(parse_cidr("2001:db8:1::5/64", true).is_err()); // host bits set
        assert!(parse_cidr("2001:db8::/0", true).is_err()); // prefix out of range
        assert!(parse_cidr("2001:db8::/127", true).is_err()); // too small
        assert!(parse_cidr("10.0.0.0/24", true).is_err()); // v4 where v6 wanted
    }

    #[test]
    fn pool_allocates_and_frees_v4() {
        // /29: network .0, server .1, clients .2-.6, broadcast .7
        let mut pool = AddressPool::new("10.99.0.0".parse().unwrap(), 29);
        let mut got = Vec::new();
        while let Some(ip) = pool.alloc() {
            got.push(ip);
        }
        assert_eq!(
            got,
            vec![
                "10.99.0.2".parse::<IpAddr>().unwrap(),
                "10.99.0.3".parse().unwrap(),
                "10.99.0.4".parse().unwrap(),
                "10.99.0.5".parse().unwrap(),
                "10.99.0.6".parse().unwrap(),
            ]
        );
        pool.free("10.99.0.4".parse().unwrap());
        assert_eq!(pool.alloc(), Some("10.99.0.4".parse().unwrap()));
        assert_eq!(pool.alloc(), None);
    }

    #[test]
    fn pool_allocates_v6() {
        // /126: network ::0, server ::1, clients ::2 and ::3.
        let mut pool = AddressPool::new("2001:db8::".parse().unwrap(), 126);
        assert_eq!(pool.alloc(), Some("2001:db8::2".parse().unwrap()));
        assert_eq!(pool.alloc(), Some("2001:db8::3".parse().unwrap()));
        assert_eq!(pool.alloc(), None); // no broadcast reserved, but ::0/::1 skipped
        pool.free("2001:db8::2".parse().unwrap());
        assert_eq!(pool.alloc(), Some("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn packet_header_extraction_v4() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45;
        pkt[12..16].copy_from_slice(&[10, 99, 0, 2]);
        pkt[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(packet_src(&pkt), Some("10.99.0.2".parse().unwrap()));
        assert_eq!(packet_dst(&pkt), Some("1.1.1.1".parse().unwrap()));
        assert_eq!(packet_src(&[0x45u8; 10]), None); // truncated
    }

    #[test]
    fn cidr_to_range_v4_v6() {
        // /16 → [10.8.0.0, 10.8.255.255]
        let r = cidr_to_range("10.8.0.0".parse().unwrap(), 16);
        assert_eq!(r.start, "10.8.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(r.end, "10.8.255.255".parse::<IpAddr>().unwrap());
        // host bits are masked off: 10.8.1.2/16 → same range
        let r2 = cidr_to_range("10.8.1.2".parse().unwrap(), 16);
        assert_eq!((r2.start, r2.end), (r.start, r.end));
        // /32 → single host
        let h = cidr_to_range("1.2.3.4".parse().unwrap(), 32);
        assert_eq!(h.start, h.end);
        // v6 /48
        let v6 = cidr_to_range("2001:db8:abcd::".parse().unwrap(), 48);
        assert_eq!(v6.start, "2001:db8:abcd::".parse::<IpAddr>().unwrap());
        assert_eq!(
            v6.end,
            "2001:db8:abcd:ffff:ffff:ffff:ffff:ffff".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn route_ranges_default_is_full_tunnel() {
        let assigned = vec![
            ("10.99.0.2".parse().unwrap(), 32u8),
            ("2001:db8::2".parse().unwrap(), 128u8),
        ];
        let r = route_ranges(&[], &assigned);
        assert_eq!(r.len(), 2);
        assert!(is_full_v4(&r[0]) && r[1].start.is_ipv6());
    }

    #[test]
    fn route_ranges_configured_ordered_and_family_filtered() {
        // v4-only client: v6 advertised route must be dropped; v4 sorted ascending.
        let assigned = vec![("10.99.0.2".parse().unwrap(), 32u8)];
        let advertised = vec![
            ("172.16.0.0".parse().unwrap(), 12u8),
            ("10.8.0.0".parse().unwrap(), 16u8),
            ("2001:db8::".parse().unwrap(), 32u8), // dropped (no v6 address)
        ];
        let r = route_ranges(&advertised, &assigned);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].start, "10.8.0.0".parse::<IpAddr>().unwrap()); // ascending
        assert_eq!(r[1].start, "172.16.0.0".parse::<IpAddr>().unwrap());
        assert!(r.iter().all(|x| x.start.is_ipv4()));
    }

    fn is_full_v4(r: &IpAddressRange) -> bool {
        r.start == "0.0.0.0".parse::<IpAddr>().unwrap()
            && r.end == "255.255.255.255".parse::<IpAddr>().unwrap()
    }

    #[test]
    fn packet_header_extraction_v6() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60;
        let src: [u8; 16] = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
        let dst: [u8; 16] = "2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets();
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        assert_eq!(packet_src(&pkt), Some("2001:db8::2".parse().unwrap()));
        assert_eq!(
            packet_dst(&pkt),
            Some("2606:4700:4700::1111".parse().unwrap())
        );
        assert_eq!(packet_src(&[0x60u8; 20]), None); // truncated v6
    }
}
