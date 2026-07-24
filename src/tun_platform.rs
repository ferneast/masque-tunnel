//! Platform backend for the CONNECT-IP client's TUN device.
//!
//! Two ownership models:
//!
//! - **Self-managed** (desktop CLI, macOS / Linux, no host fd): the client
//!   creates the device and configures its addresses with tun-rs.
//! - **Host-managed** (a `NEPacketTunnelProvider` on iOS / tvOS / macOS): the
//!   device is adopted from a host-supplied file descriptor, and addresses /
//!   routes / DNS are configured by the host (`NEIPv4Settings` / `NEIPv4Route` /
//!   `NEDNSSettings`). A provided fd always wins — the macOS network system
//!   extension's sandbox denies creating a new utun (EPERM), so ignoring the fd
//!   there breaks every connection at ADDRESS_ASSIGN time.
//!
//! Forwarding I/O (`recv` / `try_send`) is the same `AsyncDevice` on every
//! platform, so it stays in `ip_client`.

use std::net::IpAddr;

use tun_rs::AsyncDevice;

/// Adopt a host-provided utun fd as the forwarding device.
///
/// Safety: the host guarantees the fd is a valid, open utun descriptor and
/// hands ownership to the tunnel (it is closed when the device drops).
pub fn adopt_device(fd: std::os::fd::RawFd) -> std::io::Result<AsyncDevice> {
    unsafe { AsyncDevice::from_fd(fd) }
}

/// Bring up the TUN device carrying `addrs`: adopt the host-supplied fd when
/// there is one (NE provider), otherwise create the device with tun-rs.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn create_device(
    addrs: &[(IpAddr, u8)],
    mtu: u16,
    tun_name: Option<&str>,
    fd: Option<std::os::fd::RawFd>,
) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(fd) = fd {
        return Ok(adopt_device(fd)?);
    }
    let mut builder = tun_rs::DeviceBuilder::new().mtu(mtu);
    // On macOS/BSD, tun-rs otherwise installs a host route whose gateway is the
    // assigned address itself; macOS rejects it (EADDRNOTAVAIL) with a noisy
    // warning. We never want that route — traffic is steered by explicit routes.
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        builder = builder.associate_route(false);
    }
    for (addr, prefix_len) in addrs {
        builder = match addr {
            IpAddr::V4(v4) => builder.ipv4(*v4, *prefix_len, None),
            IpAddr::V6(v6) => builder.ipv6(*v6, *prefix_len),
        };
    }
    if let Some(name) = tun_name {
        builder = builder.name(name);
    }
    Ok(builder.build_async()?)
}

/// iOS / tvOS: the TUN always comes from `NEPacketTunnelProvider`, handed in as
/// a file descriptor by the FFI layer; addresses are configured by the host.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn create_device(
    _addrs: &[(IpAddr, u8)],
    _mtu: u16,
    _tun_name: Option<&str>,
    fd: Option<std::os::fd::RawFd>,
) -> Result<AsyncDevice, Box<dyn std::error::Error + Send + Sync>> {
    let fd = fd.ok_or(
        "CONNECT-IP on this platform needs a host-provided TUN fd (NEPacketTunnelProvider)",
    )?;
    Ok(adopt_device(fd)?)
}

/// The device's interface name, for logging and desktop route commands.
/// Host-managed devices have no tun-rs name.
pub fn device_name(dev: &AsyncDevice) -> String {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        dev.name().unwrap_or_else(|_| "?".into())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = dev;
        "tun".to_string()
    }
}

/// Add an address to the device. A no-op where the host (NetworkExtension)
/// configures addresses itself.
pub fn add_address(dev: &AsyncDevice, addr: IpAddr, prefix: u8) -> std::io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        match addr {
            IpAddr::V4(v4) => dev.add_address_v4(v4, prefix),
            IpAddr::V6(v6) => dev.add_address_v6(v6, prefix),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (dev, addr, prefix);
        Ok(())
    }
}

/// Remove an address from the device. A no-op where the host configures
/// addresses itself.
pub fn remove_address(dev: &AsyncDevice, addr: IpAddr) -> std::io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        dev.remove_address(addr)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (dev, addr);
        Ok(())
    }
}
