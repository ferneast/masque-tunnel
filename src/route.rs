//! Client-side route management for CONNECT-IP (RFC 9484 §4.7.3 local policy).
//!
//! When the proxy advertises routes, the client MAY install them (§4.7.3-8,
//! "subject to local policy"). We split that policy in two:
//!
//!   * **Specific ranges** (anything narrower than a default route) are added
//!     as direct routes toward the TUN. Low risk — they never touch the host's
//!     default route.
//!   * **Default routes** (`0.0.0.0/0`, `::/0`) mean full-tunnel. Taking those
//!     over is only done when the operator opts in with `--redirect-gateway`,
//!     because it reroutes *all* traffic. We then:
//!       1. pin every candidate proxy address (all DNS answers, not just the
//!          connected one) to the original gateway, so the encrypted QUIC
//!          packets keep flowing over the real link instead of recursing into
//!          the tunnel — including the handshake of a later reconnect, which
//!          may land on a different answer or address family, and
//!       2. install a split default (`0.0.0.0/1` + `128.0.0.0/1`, and the v6
//!          equivalents `::/1` + `8000::/1`) toward the TUN. A split default
//!          out-prioritizes the real default without deleting it, so rollback
//!          is a clean delete rather than a fragile restore.
//!
//! Everything installed is tracked and reverted on `Drop`. The caller must also
//! wire a signal handler (SIGINT/SIGTERM) so a Ctrl-C reverts routes instead of
//! stranding the host with a default route pointing at a dead TUN.
//!
//! DNS note: with a split default, public resolver IPs fall under the tunnel
//! and resolve through the proxy (no leak); a LAN resolver would become
//! unreachable. We do not rewrite the system resolver here.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// The host's current default gateway for one address family.
#[derive(Debug, Clone)]
pub struct Gateway {
    pub addr: IpAddr,
    pub interface: String,
}

/// The set of routes the client currently has installed on the host, kept in
/// sync with the proxy's most recent ROUTE_ADVERTISEMENT. RFC 9484 §4.7.3 is
/// declarative — each advertisement is the *complete* set — so we reconcile the
/// installed routes to match rather than accumulate. Dropping the set reverts
/// everything, restoring the host's original routing.
#[derive(Default)]
pub struct RouteSet {
    /// Direct routes currently installed toward the TUN.
    direct: HashSet<(IpAddr, u8)>,
    /// The TUN device name those routes point at.
    tun: String,
    /// Proxy-address pins (dst → (gateway, interface)), present while a default
    /// route is being redirected. Every candidate proxy address is pinned, not
    /// just the connected one, so a reconnect handshake to any of them escapes
    /// the split default.
    pins: HashMap<IpAddr, (IpAddr, String)>,
    /// Proxy addresses of the current connection attempt — the pin set to
    /// maintain while a redirect is in effect.
    candidates: Vec<IpAddr>,
}

impl RouteSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.direct.is_empty() && self.pins.is_empty()
    }

    /// Record the proxy addresses about to be dialed and, when a redirected
    /// default from a previous session is still installed, pin them to the
    /// physical gateway before the handshake. Without this, a reconnect whose
    /// DNS answer moved (or switched address family) would route its own
    /// handshake into the dead TUN. Pins for former candidates are removed.
    /// With no redirect in effect this only records the set — `reconcile`
    /// installs the pins if the session later takes over the default route.
    pub fn set_candidates(&mut self, addrs: &[IpAddr]) {
        self.candidates = addrs.to_vec();
        if self.pins.is_empty() {
            return; // no redirect in effect; nothing to escape from
        }
        let stale: Vec<IpAddr> = self
            .pins
            .keys()
            .filter(|ip| !self.candidates.contains(ip))
            .copied()
            .collect();
        for ip in stale {
            self.unpin(ip);
        }
        self.pin_all_candidates();
    }

    /// Pin every candidate, best-effort: a family without a default gateway
    /// (e.g. no IPv6 uplink) leaves that candidate unpinned — it was
    /// unreachable outside the tunnel anyway.
    fn pin_all_candidates(&mut self) {
        for ip in self.candidates.clone() {
            if let Err(e) = self.ensure_pin(ip) {
                log::warn!("[client] failed to pin proxy candidate {ip}: {e}");
            }
        }
    }

    /// Pin `dst` to the current physical default gateway (idempotent).
    fn ensure_pin(&mut self, dst: IpAddr) -> io::Result<()> {
        if self.pins.contains_key(&dst) {
            return Ok(());
        }
        let gw = default_gateway(dst.is_ipv6()).ok_or_else(|| {
            io::Error::other(format!("no default gateway found to pin proxy address {dst}"))
        })?;
        route_add_pinned(dst, gw.addr, &gw.interface)?;
        log::info!(
            "[client] pinned proxy {dst} to gateway {} dev {}",
            gw.addr,
            gw.interface
        );
        self.pins.insert(dst, (gw.addr, gw.interface));
        Ok(())
    }

    fn unpin(&mut self, dst: IpAddr) {
        let Some((gw, interface)) = self.pins.remove(&dst) else {
            return;
        };
        if let Err(e) = route_del_pinned(dst, gw, &interface) {
            log::warn!("[client] failed to remove proxy pin {dst}: {e}");
        } else {
            log::info!("[client] removed proxy pin {dst}");
        }
    }

    /// True if `ip` falls within any installed direct route (i.e. it would be
    /// routed into the tunnel). Used to check whether DNS servers are tunneled.
    pub fn covers(&self, ip: IpAddr) -> bool {
        self.direct
            .iter()
            .any(|(dst, prefix)| cidr_contains(*dst, *prefix, ip))
    }

    /// Reconcile installed routes with `ranges` (the complete advertised set).
    /// Newly advertised ranges are installed; ranges no longer present are
    /// withdrawn (declarative supersede). A default range is taken over only
    /// when `redirect_gateway` is set, pinning the proxy candidates first so
    /// the underlying QUIC connection is never routed into the tunnel it
    /// carries.
    pub fn reconcile(
        &mut self,
        ranges: &[crate::capsule::IpAddressRange],
        redirect_gateway: bool,
        proxy_ip: IpAddr,
        tun: &str,
    ) -> io::Result<()> {
        // If the device was rebuilt under a different name, drop stale routes.
        if self.tun.is_empty() {
            self.tun = tun.to_string();
        } else if self.tun != tun {
            self.revert();
            self.tun = tun.to_string();
        }

        // Desired direct-route set derived from the advertisement (declarative).
        let (desired, redirect) = desired_routes(ranges, redirect_gateway);

        // Pin the proxy candidates before installing any split default. The
        // live connection's address must escape the redirect or the tunnel
        // would swallow its own transport (hard error); the remaining
        // candidates are pinned best-effort for later reconnect handshakes.
        if redirect {
            self.ensure_pin(proxy_ip)?;
            self.pin_all_candidates();
        }

        // Install newly advertised routes.
        let to_add: Vec<_> = desired.difference(&self.direct).copied().collect();
        for (dst, prefix) in to_add {
            match route_add_direct(dst, prefix, tun) {
                Ok(()) => {
                    self.direct.insert((dst, prefix));
                    log::info!("[client] routed {dst}/{prefix} via {tun}");
                }
                Err(e) => log::error!("[client] failed to add route {dst}/{prefix}: {e}"),
            }
        }

        // Withdraw routes no longer advertised.
        let to_remove: Vec<_> = self.direct.difference(&desired).copied().collect();
        for (dst, prefix) in to_remove {
            match route_del_direct(dst, prefix, tun) {
                Ok(()) => {
                    self.direct.remove(&(dst, prefix));
                    log::info!("[client] withdrew route {dst}/{prefix}");
                }
                Err(e) => log::error!("[client] failed to remove route {dst}/{prefix}: {e}"),
            }
        }

        // Remove the proxy pins only after the split default is gone.
        if !redirect {
            for dst in self.pins.keys().copied().collect::<Vec<_>>() {
                self.unpin(dst);
            }
        }

        Ok(())
    }

    /// Revert every installed route (also runs on Drop).
    pub fn revert(&mut self) {
        let tun = self.tun.clone();
        for (dst, prefix) in self.direct.drain().collect::<Vec<_>>() {
            if let Err(e) = route_del_direct(dst, prefix, &tun) {
                log::warn!("[client] failed to remove route {dst}/{prefix}: {e}");
            }
        }
        for dst in self.pins.keys().copied().collect::<Vec<_>>() {
            self.unpin(dst);
        }
    }
}

impl Drop for RouteSet {
    fn drop(&mut self) {
        if !self.is_empty() {
            log::info!("[client] restoring original routes");
            self.revert();
        }
    }
}

/// The two halves of a split default route for the given family.
fn split_default(v6: bool) -> [(IpAddr, u8); 2] {
    if v6 {
        [
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
            (IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)), 1),
        ]
    } else {
        [
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1),
            (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
        ]
    }
}

/// True if `[start, end]` spans an entire address family (a default route).
pub fn is_default_range(start: IpAddr, end: IpAddr) -> bool {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => {
            s == Ipv4Addr::UNSPECIFIED && e == Ipv4Addr::BROADCAST
        }
        (IpAddr::V6(s), IpAddr::V6(e)) => {
            s == Ipv6Addr::UNSPECIFIED && e == Ipv6Addr::from(u128::MAX)
        }
        _ => false,
    }
}

/// True if `ip` is inside the CIDR block `net/prefix` (same family).
fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            if prefix == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// Compute the desired direct-route set for an advertisement, plus whether any
/// default route is being taken over (which requires pinning the proxy). This
/// is the pure declarative mapping: the complete advertised range set maps to
/// the complete set of routes that should be installed.
fn desired_routes(
    ranges: &[crate::capsule::IpAddressRange],
    redirect_gateway: bool,
) -> (HashSet<(IpAddr, u8)>, bool) {
    let mut desired = HashSet::new();
    let mut redirect = false;
    for r in ranges {
        if is_default_range(r.start, r.end) {
            if redirect_gateway {
                redirect = true;
                for half in split_default(r.start.is_ipv6()) {
                    desired.insert(half);
                }
            }
            // Without --redirect-gateway the default route is left untouched.
        } else {
            for cidr in range_to_cidrs(r.start, r.end) {
                desired.insert(cidr);
            }
        }
    }
    (desired, redirect)
}

/// Decompose an inclusive `[start, end]` IP range into the minimal set of
/// CIDR blocks (`addr, prefix_len`). Both ends must be the same family.
pub fn range_to_cidrs(start: IpAddr, end: IpAddr) -> Vec<(IpAddr, u8)> {
    match (start, end) {
        (IpAddr::V4(s), IpAddr::V4(e)) => cidrs_u128(u32::from(s) as u128, u32::from(e) as u128, 32)
            .into_iter()
            .map(|(a, p)| (IpAddr::V4(Ipv4Addr::from(a as u32)), p))
            .collect(),
        (IpAddr::V6(s), IpAddr::V6(e)) => cidrs_u128(u128::from(s), u128::from(e), 128)
            .into_iter()
            .map(|(a, p)| (IpAddr::V6(Ipv6Addr::from(a)), p))
            .collect(),
        _ => Vec::new(),
    }
}

/// Core range→CIDR decomposition over a `max_bits`-wide address space.
fn cidrs_u128(start: u128, end: u128, max_bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    let mut cur = start;
    loop {
        if cur > end {
            break;
        }
        // Largest block aligned at `cur`: limited by cur's trailing zeros...
        let align_bits = if cur == 0 {
            max_bits
        } else {
            cur.trailing_zeros().min(max_bits)
        };
        // ...and shrunk until the block fits within the remaining range.
        let mut bits = align_bits;
        while bits > 0 {
            let span_minus_1 = if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 };
            if span_minus_1 <= end - cur {
                break;
            }
            bits -= 1;
        }
        out.push((cur, (max_bits - bits) as u8));
        // Advance; stop cleanly if the block reached the top of the space.
        if bits >= 128 {
            break;
        }
        match cur.checked_add(1u128 << bits) {
            Some(next) => cur = next,
            None => break,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Platform default-gateway lookup and route mutation.
// ---------------------------------------------------------------------------

/// Look up the host's current default gateway for the given family.
#[cfg(target_os = "macos")]
pub fn default_gateway(v6: bool) -> Option<Gateway> {
    // `route -n get -inet[6] default` prints "gateway: X" and "interface: Y".
    let inet = if v6 { "-inet6" } else { "-inet" };
    let out = Command::new("route")
        .args(["-n", "get", inet, "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut gw = None;
    let mut interface = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("gateway:") {
            gw = v.trim().parse::<IpAddr>().ok();
        } else if let Some(v) = line.strip_prefix("interface:") {
            interface = Some(v.trim().to_string());
        }
    }
    // A default route may have only an interface (point-to-point); require a
    // gateway address to pin against.
    Some(Gateway {
        addr: gw?,
        interface: interface?,
    })
}

#[cfg(target_os = "linux")]
pub fn default_gateway(v6: bool) -> Option<Gateway> {
    // `ip -4/-6 route show default` prints "default via X dev Y ...".
    let fam = if v6 { "-6" } else { "-4" };
    let out = Command::new("ip")
        .args([fam, "route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    let toks: Vec<&str> = first.split_whitespace().collect();
    let mut gw = None;
    let mut interface = None;
    let mut i = 0;
    while i + 1 < toks.len() {
        match toks[i] {
            "via" => gw = toks[i + 1].parse::<IpAddr>().ok(),
            "dev" => interface = Some(toks[i + 1].to_string()),
            _ => {}
        }
        i += 1;
    }
    Some(Gateway {
        addr: gw?,
        interface: interface?,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn default_gateway(_v6: bool) -> Option<Gateway> {
    None
}

/// Run a route command, mapping "file exists"/"already in table" to success so
/// re-adding an existing route is not fatal.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_route(cmd: &mut Command, action: &str) -> io::Result<()> {
    let out = cmd.output()?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    if stderr.contains("exists") || stderr.contains("already") {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{action} failed: {}",
        stderr.trim()
    )))
}

#[cfg(target_os = "macos")]
fn route_add_direct(dst: IpAddr, prefix: u8, tun: &str) -> io::Result<()> {
    let net = if dst.is_ipv6() { "-inet6" } else { "-inet" };
    run_route(
        Command::new("route").args([
            "-n", "add", net, "-net",
            &format!("{dst}/{prefix}"), "-interface", tun,
        ]),
        "route add",
    )
}

#[cfg(target_os = "linux")]
fn route_add_direct(dst: IpAddr, prefix: u8, tun: &str) -> io::Result<()> {
    let fam = if dst.is_ipv6() { "-6" } else { "-4" };
    run_route(
        Command::new("ip").args([
            fam, "route", "add", &format!("{dst}/{prefix}"), "dev", tun,
        ]),
        "ip route add",
    )
}

#[cfg(target_os = "macos")]
fn route_del_direct(dst: IpAddr, prefix: u8, _tun: &str) -> io::Result<()> {
    let net = if dst.is_ipv6() { "-inet6" } else { "-inet" };
    run_route(
        Command::new("route").args(["-n", "delete", net, "-net", &format!("{dst}/{prefix}")]),
        "route delete",
    )
}

#[cfg(target_os = "linux")]
fn route_del_direct(dst: IpAddr, prefix: u8, tun: &str) -> io::Result<()> {
    let fam = if dst.is_ipv6() { "-6" } else { "-4" };
    run_route(
        Command::new("ip").args([
            fam, "route", "del", &format!("{dst}/{prefix}"), "dev", tun,
        ]),
        "ip route del",
    )
}

#[cfg(target_os = "macos")]
fn route_add_pinned(dst: IpAddr, gw: IpAddr, _interface: &str) -> io::Result<()> {
    let net = if dst.is_ipv6() { "-inet6" } else { "-inet" };
    run_route(
        Command::new("route").args([
            "-n", "add", net, "-host", &dst.to_string(), &gw.to_string(),
        ]),
        "route add (pin)",
    )
}

#[cfg(target_os = "linux")]
fn route_add_pinned(dst: IpAddr, gw: IpAddr, interface: &str) -> io::Result<()> {
    let fam = if dst.is_ipv6() { "-6" } else { "-4" };
    let host = if dst.is_ipv6() { format!("{dst}/128") } else { format!("{dst}/32") };
    run_route(
        Command::new("ip").args([
            fam, "route", "add", &host, "via", &gw.to_string(), "dev", interface,
        ]),
        "ip route add (pin)",
    )
}

#[cfg(target_os = "macos")]
fn route_del_pinned(dst: IpAddr, _gw: IpAddr, _interface: &str) -> io::Result<()> {
    let net = if dst.is_ipv6() { "-inet6" } else { "-inet" };
    run_route(
        Command::new("route").args(["-n", "delete", net, "-host", &dst.to_string()]),
        "route delete (pin)",
    )
}

#[cfg(target_os = "linux")]
fn route_del_pinned(dst: IpAddr, _gw: IpAddr, _interface: &str) -> io::Result<()> {
    let fam = if dst.is_ipv6() { "-6" } else { "-4" };
    let host = if dst.is_ipv6() { format!("{dst}/128") } else { format!("{dst}/32") };
    run_route(
        Command::new("ip").args([fam, "route", "del", &host]),
        "ip route del (pin)",
    )
}

// Non-macOS/Linux: routing is unsupported; surface a clear error at call time.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_add_direct(_dst: IpAddr, _prefix: u8, _tun: &str) -> io::Result<()> {
    Err(io::Error::other("automatic routing unsupported on this platform"))
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_del_direct(_dst: IpAddr, _prefix: u8, _tun: &str) -> io::Result<()> {
    Ok(())
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_add_pinned(_dst: IpAddr, _gw: IpAddr, _interface: &str) -> io::Result<()> {
    Err(io::Error::other("automatic routing unsupported on this platform"))
}
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn route_del_pinned(_dst: IpAddr, _gw: IpAddr, _interface: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn default_range_detected() {
        assert!(is_default_range(v4("0.0.0.0"), v4("255.255.255.255")));
        assert!(is_default_range(v6("::"), v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")));
        assert!(!is_default_range(v4("10.0.0.0"), v4("10.255.255.255")));
        assert!(!is_default_range(v4("0.0.0.0"), v4("127.255.255.255")));
    }

    #[test]
    fn full_v4_range_is_one_default_cidr() {
        assert_eq!(
            range_to_cidrs(v4("0.0.0.0"), v4("255.255.255.255")),
            vec![(v4("0.0.0.0"), 0)]
        );
    }

    #[test]
    fn full_v6_range_is_one_default_cidr() {
        assert_eq!(
            range_to_cidrs(v6("::"), v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            vec![(v6("::"), 0)]
        );
    }

    #[test]
    fn aligned_block_is_single_cidr() {
        assert_eq!(
            range_to_cidrs(v4("10.0.0.0"), v4("10.255.255.255")),
            vec![(v4("10.0.0.0"), 8)]
        );
        assert_eq!(
            range_to_cidrs(v4("192.168.1.0"), v4("192.168.1.255")),
            vec![(v4("192.168.1.0"), 24)]
        );
    }

    #[test]
    fn single_host_is_full_prefix() {
        assert_eq!(
            range_to_cidrs(v4("1.1.1.1"), v4("1.1.1.1")),
            vec![(v4("1.1.1.1"), 32)]
        );
    }

    #[test]
    fn unaligned_range_splits_minimally() {
        // 10.0.0.0 - 10.0.0.5 = /29 (0-7)? No: must not overshoot 5.
        // 0..=5 => 10.0.0.0/30 (0-3) + 10.0.0.4/31 (4-5)
        assert_eq!(
            range_to_cidrs(v4("10.0.0.0"), v4("10.0.0.5")),
            vec![(v4("10.0.0.0"), 30), (v4("10.0.0.4"), 31)]
        );
    }

    #[test]
    fn split_default_halves() {
        assert_eq!(
            split_default(false),
            [(v4("0.0.0.0"), 1), (v4("128.0.0.0"), 1)]
        );
        assert_eq!(split_default(true), [(v6("::"), 1), (v6("8000::"), 1)]);
    }

    fn range(s: &str, e: &str) -> crate::capsule::IpAddressRange {
        crate::capsule::IpAddressRange {
            start: s.parse().unwrap(),
            end: e.parse().unwrap(),
            ip_proto: 0,
        }
    }

    #[test]
    fn desired_specific_ranges() {
        let r = vec![
            range("10.0.0.0", "10.255.255.255"),
            range("192.168.1.0", "192.168.1.255"),
        ];
        let (d, redirect) = desired_routes(&r, false);
        assert!(!redirect);
        assert_eq!(
            d,
            HashSet::from([(v4("10.0.0.0"), 8), (v4("192.168.1.0"), 24)])
        );
    }

    #[test]
    fn desired_default_needs_optin() {
        let r = vec![range("0.0.0.0", "255.255.255.255")];
        // Without opt-in: no routes installed, no redirect.
        let (d, redirect) = desired_routes(&r, false);
        assert!(d.is_empty());
        assert!(!redirect);
        // With opt-in: split default + redirect flag set.
        let (d, redirect) = desired_routes(&r, true);
        assert!(redirect);
        assert_eq!(d, HashSet::from([(v4("0.0.0.0"), 1), (v4("128.0.0.0"), 1)]));
    }

    #[test]
    fn desired_withdraw_by_omission() {
        // Declarative: dropping a range from the advertisement drops it from the
        // desired set, so reconcile withdraws the delta.
        let full = vec![
            range("10.0.0.0", "10.255.255.255"),
            range("172.16.0.0", "172.16.255.255"),
        ];
        let (before, _) = desired_routes(&full, false);
        let reduced = vec![range("10.0.0.0", "10.255.255.255")];
        let (after, _) = desired_routes(&reduced, false);
        assert!(before.contains(&(v4("172.16.0.0"), 16)));
        assert!(!after.contains(&(v4("172.16.0.0"), 16)));
        assert!(after.contains(&(v4("10.0.0.0"), 8)));
    }

    #[test]
    fn desired_empty_advertisement_withdraws_all() {
        let (d, redirect) = desired_routes(&[], true);
        assert!(d.is_empty());
        assert!(!redirect);
    }

    #[test]
    fn cidr_contains_matches() {
        // Split-default halves partition the v4 space.
        assert!(cidr_contains(v4("0.0.0.0"), 1, v4("1.1.1.1")));
        assert!(cidr_contains(v4("128.0.0.0"), 1, v4("202.96.134.133")));
        assert!(!cidr_contains(v4("128.0.0.0"), 1, v4("1.1.1.1")));
        // Specific prefix.
        assert!(cidr_contains(v4("10.0.0.0"), 8, v4("10.5.5.5")));
        assert!(!cidr_contains(v4("10.0.0.0"), 8, v4("11.0.0.1")));
        // /0 covers everything; mixed family never matches.
        assert!(cidr_contains(v4("0.0.0.0"), 0, v4("8.8.8.8")));
        assert!(!cidr_contains(v4("0.0.0.0"), 0, v6("2001:db8::1")));
    }
}
