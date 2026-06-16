//! Manual check for CONNECT-UDP target parsing (RFC 9298).
//!
//! Run with: `cargo run --example uritest`
//!
//! For each input it prints the path the client would build, the (host, port)
//! the server would parse back, and which connection path the server takes:
//! IP literals connect directly, hostnames go through DNS resolution.

use std::net::IpAddr;

use masque_tunnel::common::{encode_target_host, parse_connect_udp_path, CONNECT_UDP_PATH};

fn check(target_host: &str, port: u16) {
    let encoded = encode_target_host(target_host);
    let path = format!("{CONNECT_UDP_PATH}/{encoded}/{port}/");
    let parsed = parse_connect_udp_path(&path);
    let route = match &parsed {
        Some((host, _)) if host.parse::<IpAddr>().is_ok() => "direct (IP literal)",
        Some(_) => "DNS lookup (hostname)",
        None => "PARSE FAILED",
    };
    println!("  in   = {target_host}:{port}");
    println!("  path = {path}");
    println!("  out  = {parsed:?}");
    println!("  route= {route}\n");
}

fn main() {
    println!("== hostname (the common case) ==");
    check("host1.example.com", 7521);

    println!("== hostname already bracketless ==");
    check("proxy.example.org", 443);

    println!("== IPv4 literal ==");
    check("192.0.2.6", 443);

    println!("== IPv6 literal, bracketed input (RFC 3849 doc prefix) ==");
    check("[2001:db8:101:1228::4d23]", 29381);

    println!("== IPv6 literal, bare input ==");
    check("2001:db8::42", 443);

    // Assertions: hostnames must round-trip untouched and route via DNS.
    let (host, port) =
        parse_connect_udp_path(&format!("{CONNECT_UDP_PATH}/host1.example.com/7521/")).unwrap();
    assert_eq!((host.as_str(), port), ("host1.example.com", 7521));
    assert!(
        host.parse::<IpAddr>().is_err(),
        "hostname must NOT be treated as an IP literal"
    );
    println!("OK: hostname parses cleanly and is routed to DNS resolution.");
}
