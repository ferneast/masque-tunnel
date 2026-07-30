//! System DNS takeover for CONNECT-IP (RFC 9484 assigns addresses and routes
//! but no resolver, so DNS is local policy).
//!
//! When `--dns` is given, the client points the system resolver at those
//! servers while the tunnel is up and restores the original configuration on
//! exit (Drop, wired to the same SIGINT/SIGTERM handler as routes). Without
//! `--dns`, resolvers pushed by the proxy (DNS_ASSIGN) are adopted instead,
//! and a later push with a different set replaces them in place — the pushed
//! set is declarative proxy state, surviving reconfiguration across
//! reconnects, not a one-shot override. This is independent of
//! `--redirect-gateway`: taking over DNS and taking over the default route are
//! orthogonal. If the chosen resolvers are not actually
//! routed through the tunnel, queries would go out in cleartext, so we log a
//! leak warning in that case — but do not refuse (a LAN resolver reached over
//! a split tunnel may be exactly what the operator wants).
//!
//! macOS: `networksetup -setdnsservers` per enabled network service, saving
//! and restoring each service's prior servers. Linux: overwrite
//! `/etc/resolv.conf`, backing up and restoring its contents. The Linux path
//! is best-effort — on systemd-resolved hosts `/etc/resolv.conf` may be a
//! managed symlink that gets regenerated.

use std::io;
use std::net::IpAddr;
// Only macOS uses Command (networksetup); Linux rewrites /etc/resolv.conf.
#[cfg(target_os = "macos")]
use std::process::Command;

/// RAII system-DNS override. Applying is idempotent; the original configuration
/// is restored on `revert()` and on Drop. Servers set by the operator (`--dns`)
/// are permanent for the process; servers adopted from a DNS_ASSIGN are
/// declaratively replaced when a later DNS_ASSIGN (e.g. after a reconnect to a
/// reconfigured proxy) carries a different set.
pub struct DnsGuard {
    servers: Vec<IpAddr>,
    /// True when `servers` came from `--dns`: pushed sets are then ignored.
    explicit: bool,
    applied: bool,
    #[cfg(target_os = "macos")]
    saved: Vec<(String, Vec<String>)>,
    #[cfg(target_os = "linux")]
    saved: Option<Vec<u8>>,
}

impl DnsGuard {
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self {
            explicit: !servers.is_empty(),
            servers,
            applied: false,
            #[cfg(target_os = "macos")]
            saved: Vec::new(),
            #[cfg(target_os = "linux")]
            saved: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        !self.servers.is_empty()
    }

    /// Apply the DNS override once. `routes` is consulted only to decide whether
    /// the chosen servers actually route through the tunnel (leak warning).
    pub fn ensure_applied(&mut self, routes: &crate::route::RouteSet) -> io::Result<()> {
        if self.applied || self.servers.is_empty() {
            return Ok(());
        }
        self.warn_if_leaky(routes);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            #[cfg(target_os = "macos")]
            {
                self.saved = apply_macos(&self.servers)?;
            }
            #[cfg(target_os = "linux")]
            {
                self.saved = apply_linux(&self.servers)?;
            }
            self.applied = true;
            log::info!(
                "[client] system DNS set to {:?} (restored on exit)",
                self.servers
            );
        }
        // Other platforms (iOS/tvOS): the host's NetworkExtension configures the
        // resolver (`NEDNSSettings`), so there is nothing to apply here.
        Ok(())
    }

    /// Adopt server-pushed resolvers from a DNS_ASSIGN capsule
    /// (draft-ietf-masque-connect-ip-dns) and apply them. An explicit `--dns`
    /// wins: the pushed set is then ignored. A set adopted from an earlier
    /// DNS_ASSIGN is declarative state, not an override: a later push with a
    /// different set (a reconnect to a reconfigured proxy) replaces it in
    /// place, so the client never keeps resolving through a resolver the proxy
    /// has moved away from. Returns whether the pushed set is in effect.
    pub fn adopt_pushed(
        &mut self,
        servers: Vec<IpAddr>,
        routes: &crate::route::RouteSet,
    ) -> io::Result<bool> {
        // An empty push is not a withdrawal (the draft defines none); ignore it.
        if servers.is_empty() {
            return Ok(false);
        }
        match adopt_action(self.explicit, self.applied, &self.servers, &servers) {
            AdoptAction::Ignore => Ok(false),
            AdoptAction::Unchanged => Ok(true),
            AdoptAction::Adopt => {
                self.servers = servers;
                self.ensure_applied(routes)?;
                Ok(true)
            }
            AdoptAction::Replace => {
                self.servers = servers;
                self.warn_if_leaky(routes);
                self.reapply()?;
                Ok(true)
            }
        }
    }

    /// Warn when the chosen servers are not routed through the tunnel, so
    /// cleartext queries don't go unnoticed (still allowed — a LAN resolver
    /// over a split tunnel may be intended).
    fn warn_if_leaky(&self, routes: &crate::route::RouteSet) {
        if !self.servers.iter().all(|s| routes.covers(*s)) {
            log::warn!(
                "[client] DNS {:?} is not routed through the tunnel; DNS queries may go out \
                 in cleartext (add --redirect-gateway, or route the resolver's range)",
                self.servers
            );
        }
    }

    /// Rewrite the system resolver to the current server set while keeping the
    /// configuration saved before the *first* takeover, so `revert()` still
    /// restores the pre-tunnel state rather than an intermediate override.
    fn reapply(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let wanted: Vec<String> = self.servers.iter().map(|s| s.to_string()).collect();
            for (svc, _original) in &self.saved {
                set_dns(svc, &wanted)?;
            }
        }
        #[cfg(target_os = "linux")]
        write_resolv_conf(&self.servers)?;
        log::info!("[client] system DNS updated to {:?}", self.servers);
        Ok(())
    }

    /// Restore the original DNS configuration (also runs on Drop).
    pub fn revert(&mut self) {
        if !self.applied {
            return;
        }
        #[cfg(target_os = "macos")]
        revert_macos(&self.saved);
        #[cfg(target_os = "linux")]
        revert_linux(&self.saved);
        self.applied = false;
        log::info!("[client] system DNS restored");
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        self.revert();
    }
}

/// What a (non-empty) DNS_ASSIGN does to the guard, given its current state.
#[derive(Debug, PartialEq, Eq)]
enum AdoptAction {
    /// Explicit `--dns` wins; the push is ignored.
    Ignore,
    /// The pushed set is already in effect; nothing to do.
    Unchanged,
    /// Nothing applied yet: adopt the pushed set and take over the resolver.
    Adopt,
    /// A different pushed set is applied: rewrite the resolver in place.
    Replace,
}

fn adopt_action(
    explicit: bool,
    applied: bool,
    current: &[IpAddr],
    pushed: &[IpAddr],
) -> AdoptAction {
    if explicit {
        AdoptAction::Ignore
    } else if !applied {
        AdoptAction::Adopt
    } else if current == pushed {
        AdoptAction::Unchanged
    } else {
        AdoptAction::Replace
    }
}

// ---------------------------------------------------------------------------
// macOS: networksetup per network service.
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn list_services() -> io::Result<Vec<String>> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .skip(1) // first line is the asterisk legend
        .filter(|l| !l.starts_with('*')) // '*' marks a disabled service
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

#[cfg(target_os = "macos")]
fn get_dns(service: &str) -> Vec<String> {
    let Ok(out) = Command::new("networksetup")
        .arg("-getdnsservers")
        .arg(service)
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // "There aren't any DNS Servers set on <svc>." means DHCP-provided.
    if text.contains("aren't any") {
        return Vec::new();
    }
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.parse::<IpAddr>().is_ok())
        .collect()
}

#[cfg(target_os = "macos")]
fn set_dns(service: &str, servers: &[String]) -> io::Result<()> {
    let mut cmd = Command::new("networksetup");
    cmd.arg("-setdnsservers").arg(service);
    if servers.is_empty() {
        cmd.arg("Empty"); // clears manual servers, back to DHCP
    } else {
        for s in servers {
            cmd.arg(s);
        }
    }
    let out = cmd.output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn apply_macos(servers: &[IpAddr]) -> io::Result<Vec<(String, Vec<String>)>> {
    let wanted: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let mut saved = Vec::new();
    for svc in list_services()? {
        let original = get_dns(&svc);
        set_dns(&svc, &wanted)?;
        saved.push((svc, original));
    }
    Ok(saved)
}

#[cfg(target_os = "macos")]
fn revert_macos(saved: &[(String, Vec<String>)]) {
    for (svc, original) in saved {
        if let Err(e) = set_dns(svc, original) {
            log::warn!("[client] failed to restore DNS on {svc}: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Linux: /etc/resolv.conf.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn write_resolv_conf(servers: &[IpAddr]) -> io::Result<()> {
    let mut content = String::from("# written by masque-ip; restored on exit\n");
    for s in servers {
        content.push_str(&format!("nameserver {s}\n"));
    }
    std::fs::write("/etc/resolv.conf", content)
}

#[cfg(target_os = "linux")]
fn apply_linux(servers: &[IpAddr]) -> io::Result<Option<Vec<u8>>> {
    let original = std::fs::read("/etc/resolv.conf").ok();
    write_resolv_conf(servers)?;
    Ok(original)
}

#[cfg(target_os = "linux")]
fn revert_linux(saved: &Option<Vec<u8>>) {
    let res = match saved {
        Some(original) => std::fs::write("/etc/resolv.conf", original),
        None => std::fs::remove_file("/etc/resolv.conf"),
    };
    if let Err(e) = res {
        log::warn!("[client] failed to restore /etc/resolv.conf: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn explicit_dns_ignores_pushes() {
        assert_eq!(
            adopt_action(true, true, &ips(&["10.0.0.1"]), &ips(&["10.0.0.2"])),
            AdoptAction::Ignore
        );
    }

    #[test]
    fn first_push_is_adopted() {
        assert_eq!(
            adopt_action(false, false, &[], &ips(&["10.0.0.1"])),
            AdoptAction::Adopt
        );
    }

    #[test]
    fn identical_push_is_a_noop() {
        assert_eq!(
            adopt_action(false, true, &ips(&["10.0.0.1"]), &ips(&["10.0.0.1"])),
            AdoptAction::Unchanged
        );
    }

    #[test]
    fn changed_push_replaces_the_adopted_set() {
        assert_eq!(
            adopt_action(false, true, &ips(&["10.0.0.1"]), &ips(&["10.0.0.2"])),
            AdoptAction::Replace
        );
    }

    #[test]
    fn failed_apply_is_retried_as_adopt() {
        // servers were set by an earlier push but applying them failed:
        // the next push must retry the takeover, not pretend it is in effect.
        assert_eq!(
            adopt_action(false, false, &ips(&["10.0.0.1"]), &ips(&["10.0.0.1"])),
            AdoptAction::Adopt
        );
    }
}
