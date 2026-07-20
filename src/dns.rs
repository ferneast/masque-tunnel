//! System DNS takeover for CONNECT-IP (RFC 9484 assigns addresses and routes
//! but no resolver, so DNS is local policy).
//!
//! When `--dns` is given, the client points the system resolver at those
//! servers while the tunnel is up and restores the original configuration on
//! exit (Drop, wired to the same SIGINT/SIGTERM handler as routes). This is
//! independent of `--redirect-gateway`: taking over DNS and taking over the
//! default route are orthogonal. If the chosen resolvers are not actually
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::process::Command;

/// RAII system-DNS override. Applying is idempotent; the original configuration
/// is restored on `revert()` and on Drop.
pub struct DnsGuard {
    servers: Vec<IpAddr>,
    applied: bool,
    #[cfg(target_os = "macos")]
    saved: Vec<(String, Vec<String>)>,
    #[cfg(target_os = "linux")]
    saved: Option<Vec<u8>>,
}

impl DnsGuard {
    pub fn new(servers: Vec<IpAddr>) -> Self {
        Self {
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
        if !self.servers.iter().all(|s| routes.covers(*s)) {
            log::warn!(
                "[client] --dns {:?} is not routed through the tunnel; DNS queries may go out \
                 in cleartext (add --redirect-gateway, or route the resolver's range)",
                self.servers
            );
        }
        #[cfg(target_os = "macos")]
        {
            self.saved = apply_macos(&self.servers)?;
        }
        #[cfg(target_os = "linux")]
        {
            self.saved = apply_linux(&self.servers)?;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            return Err(io::Error::other(
                "--dns is not supported on this platform",
            ));
        }
        self.applied = true;
        log::info!(
            "[client] system DNS set to {:?} (restored on exit)",
            self.servers
        );
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
fn apply_linux(servers: &[IpAddr]) -> io::Result<Option<Vec<u8>>> {
    let original = std::fs::read("/etc/resolv.conf").ok();
    let mut content = String::from("# written by masque-tunnel; restored on exit\n");
    for s in servers {
        content.push_str(&format!("nameserver {s}\n"));
    }
    std::fs::write("/etc/resolv.conf", content)?;
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
