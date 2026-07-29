pub mod capsule;
pub mod client;
pub mod common;
pub mod dns;
pub mod ffi;
pub mod icmp;
pub mod ip_client;
// Server side needs a tun-rs-created device; iOS/tvOS build only the client.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod ip_server;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod masquerade;
pub mod route;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod server;
pub mod tun_platform;
