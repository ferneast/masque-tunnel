pub mod capsule;
pub mod client;
pub mod common;
pub mod dns;
pub mod ffi;
pub mod icmp;
pub mod ip_client;
// The server side builds its own TUN with tun-rs `DeviceBuilder`, which does
// not exist on iOS/tvOS. A MASQUE proxy only runs on desktop/server platforms,
// so gate it there; the client core stays cross-platform.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod ip_server;
pub mod route;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod server;
pub mod tun_platform;
