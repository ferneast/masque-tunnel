//! C ABI for embedding the CONNECT-IP client in a host tunnel provider
//! (iOS / tvOS `NEPacketTunnelProvider`).
//!
//! The host creates the utun, hands us a **dup** of its file descriptor
//! (`masque_client_ip_start` takes ownership and closes it on stop), and
//! programs `NEIPv4Settings` / routes / DNS from the callbacks — the Rust core
//! only does QUIC + CONNECT-IP + packet forwarding over that fd.
//!
//! The client runs on a dedicated thread with a current-thread Tokio runtime,
//! so the forwarding future need not be `Send`. `masque_client_ip_stop` signals
//! shutdown and joins the thread. Callbacks are invoked from that worker thread;
//! the host implementation must be thread-safe.

use std::ffi::{c_char, c_void, CStr, CString};
use std::net::IpAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::capsule::IpAddressRange;
use crate::ip_client::{self, ClientEvents, IpClientConfig, TunFdSlot, TunnelStats};

/// Host callbacks. Function pointers and `ctx` must stay valid until
/// `masque_client_ip_stop` returns.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MasqueCallbacks {
    pub ctx: *mut c_void,
    /// JSON array: `[{"addr":"10.99.0.2","prefix":32}, …]`.
    pub on_addresses: extern "C" fn(ctx: *mut c_void, addrs_json: *const c_char),
    /// JSON array of CIDRs expanded from the advertised ranges:
    /// `[{"addr":"0.0.0.0","prefix":0,"proto":0}, …]` (`proto` 0 = all,
    /// otherwise an IANA Internet Protocol Number).
    pub on_routes: extern "C" fn(ctx: *mut c_void, routes_json: *const c_char),
    /// `state`: 0 = connecting, 1 = established, 2 = error. `detail` may be null.
    pub on_state: extern "C" fn(ctx: *mut c_void, state: i32, detail: *const c_char),
    /// JSON array of DNS resolver addresses: `["8.8.8.8","2001:4860:4860::8888"]`
    /// (DNS_ASSIGN, draft-ietf-masque-connect-ip-dns). The host programs
    /// `NEDNSSettings` from these. Called only when the proxy advertises DNS.
    pub on_dns: extern "C" fn(ctx: *mut c_void, dns_json: *const c_char),
    /// The tunnel dropped and `auto_reconnect` was false at start: the client
    /// is holding until the host triggers the retry. The host prepares the
    /// platform (set the provider reasserting) and calls
    /// `masque_client_ip_reconnect`. Never called with `auto_reconnect` true.
    pub on_retry: extern "C" fn(ctx: *mut c_void, detail: *const c_char),
}

// The host guarantees the pointers stay valid for the tunnel's lifetime.
unsafe impl Send for MasqueCallbacks {}
unsafe impl Sync for MasqueCallbacks {}

/// Log sink: `level` 0 = error, 1 = warn, 2 = info, 3 = debug/trace.
pub type MasqueLogCallback = extern "C" fn(level: i32, message: *const c_char);

// Stored as a usize so the hot log path is a single atomic load; 0 = unset.
static LOG_CB: AtomicUsize = AtomicUsize::new(0);

struct FfiLogger;

impl log::Log for FfiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // Forward this crate's own lines up to Debug, but only Warn+ from
        // dependencies. quinn's `log` feature (and h3 / rustls) emit an
        // extremely chatty per-poll stream (e.g. "drive; id=0") at Debug/Trace
        // that would otherwise flood the host log across the FFI boundary.
        if metadata.target().starts_with("masque_tunnel") {
            metadata.level() <= log::Level::Debug
        } else {
            metadata.level() <= log::Level::Warn
        }
    }
    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let cb = LOG_CB.load(Ordering::Acquire);
        if cb == 0 {
            return;
        }
        let cb: MasqueLogCallback = unsafe { std::mem::transmute(cb) };
        let level = match record.level() {
            log::Level::Error => 0,
            log::Level::Warn => 1,
            log::Level::Info => 2,
            _ => 3,
        };
        if let Ok(msg) = CString::new(format!("{}", record.args())) {
            cb(level, msg.as_ptr());
        }
    }
    fn flush(&self) {}
}

static LOGGER: FfiLogger = FfiLogger;

/// Route Rust `log` output to `callback`. Call once, before
/// `masque_client_ip_start`; the callback must stay valid for the process
/// lifetime and be callable from any thread.
#[no_mangle]
pub extern "C" fn masque_set_log_callback(callback: MasqueLogCallback) {
    LOG_CB.store(callback as usize, Ordering::Release);
    // Ignore the error on repeat calls: the logger is already installed and
    // keeps reading the (updated) callback from LOG_CB.
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}

struct HostEvents {
    cb: MasqueCallbacks,
}

impl ClientEvents for HostEvents {
    fn addresses_assigned(&self, addrs: &[(IpAddr, u8)]) {
        if let Ok(json) = CString::new(addrs_json(addrs)) {
            (self.cb.on_addresses)(self.cb.ctx, json.as_ptr());
        }
    }
    fn routes_advertised(&self, ranges: &[IpAddressRange]) {
        if let Ok(json) = CString::new(routes_json(ranges)) {
            (self.cb.on_routes)(self.cb.ctx, json.as_ptr());
        }
    }
    fn dns_assigned(&self, servers: &[IpAddr]) {
        if let Ok(json) = CString::new(dns_json(servers)) {
            (self.cb.on_dns)(self.cb.ctx, json.as_ptr());
        }
    }
    fn reconnect_needed(&self, detail: &str) {
        // An interior NUL in the error text must not swallow the event; the
        // host needs the wake-up more than the detail.
        let detail = CString::new(detail).unwrap_or_default();
        (self.cb.on_retry)(self.cb.ctx, detail.as_ptr());
    }
}

fn dns_json(servers: &[IpAddr]) -> String {
    let items: Vec<String> = servers.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", items.join(","))
}

fn addrs_json(addrs: &[(IpAddr, u8)]) -> String {
    let items: Vec<String> = addrs
        .iter()
        .map(|(a, p)| format!("{{\"addr\":\"{a}\",\"prefix\":{p}}}"))
        .collect();
    format!("[{}]", items.join(","))
}

fn routes_json(ranges: &[IpAddressRange]) -> String {
    let items: Vec<String> = ranges
        .iter()
        .flat_map(|r| {
            let proto = r.ip_proto;
            crate::route::range_to_cidrs(r.start, r.end)
                .into_iter()
                .map(move |(addr, prefix)| {
                    format!("{{\"addr\":\"{addr}\",\"prefix\":{prefix},\"proto\":{proto}}}")
                })
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Opaque handle owning the worker thread, its graceful-shutdown signal, the
/// traffic counters, and the immediate-reconnect signal.
pub struct MasqueHandle {
    shutdown: Arc<tokio::sync::Notify>,
    thread: Option<std::thread::JoinHandle<()>>,
    stats: Arc<TunnelStats>,
    reconnect: Arc<tokio::sync::Notify>,
    tun_fd: Arc<TunFdSlot>,
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(str::to_owned)
}

/// Start the CONNECT-IP client against `proxy_url`, forwarding over `tun_fd`
/// (a dup of the provider's utun fd). `auth_token`, `sni`, and
/// `preferred_addresses` may be null; `mtu` 0 selects the default (1280).
/// `preferred_addresses` is a comma-separated list of IP literals (e.g.
/// `"10.99.0.2,2001:db8::2"`) preferred on a cold start, before any address is
/// assigned, so the proxy can hand back a stable IP; the first entry of each
/// family is used. Null, empty, or unparseable entries keep the previous "no
/// preference" behavior. With `auto_reconnect` the client retries dropped
/// tunnels itself (backoff); without it each drop fires `on_retry` and the
/// client holds until `masque_client_ip_reconnect` — for hosts that must
/// prepare the platform first (iOS reasserting). Returns an opaque handle, or
/// null on invalid input.
///
/// # Safety
/// `proxy_url` must be a valid NUL-terminated UTF-8 string; `auth_token`,
/// `sni`, and `preferred_addresses` the same or null. `callbacks` pointers must
/// remain valid until stop.
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_start(
    proxy_url: *const c_char,
    auth_token: *const c_char,
    sni: *const c_char,
    preferred_addresses: *const c_char,
    insecure: bool,
    auto_reconnect: bool,
    mtu: u16,
    tun_fd: RawFd,
    callbacks: MasqueCallbacks,
) -> *mut MasqueHandle {
    let Some(proxy_url) = cstr(proxy_url) else {
        return std::ptr::null_mut();
    };
    let auth_token = cstr(auth_token);
    let sni = cstr(sni);
    let preferred_addresses: Vec<IpAddr> = cstr(preferred_addresses)
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .filter_map(|t| match t.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => {
                        log::warn!("[client] ignoring invalid preferred address: {t}");
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let stats = Arc::new(TunnelStats::default());
    let reconnect = Arc::new(tokio::sync::Notify::new());
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let tun_fd_slot = Arc::new(TunFdSlot::new(tun_fd));

    let config = IpClientConfig {
        proxy_url,
        sni,
        auth_token,
        insecure,
        ca: None,
        mtu: if mtu == 0 { 1280 } else { mtu },
        tun_name: None,
        redirect_gateway: false,
        dns: Vec::new(),
        tun_fd: Some(tun_fd_slot.clone()),
        events: Some(Arc::new(HostEvents { cb: callbacks })),
        stats: Some(stats.clone()),
        reconnect: Some(reconnect.clone()),
        shutdown: Some(shutdown.clone()),
        preferred_addresses,
        auto_reconnect,
    };

    let thread = std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                report_error(&callbacks, &format!("runtime init failed: {e}"));
                return;
            }
        };
        rt.block_on(async move {
            (callbacks.on_state)(callbacks.ctx, 0, std::ptr::null()); // connecting
            // `run` loops forever reconnecting; it returns cleanly once the host
            // signals shutdown (having closed the connection gracefully), or on a
            // fatal setup error, which we surface to the host.
            if let Err(e) = ip_client::run(config).await {
                report_error(&callbacks, &e.to_string());
            }
        });
    });

    Box::into_raw(Box::new(MasqueHandle {
        shutdown,
        thread: Some(thread),
        stats,
        reconnect,
        tun_fd: tun_fd_slot,
    }))
}

/// Hand the client a replacement TUN fd (a dup of the provider's current utun
/// fd; the client takes ownership). Call after a tunnel-settings apply rebuilt
/// the interface (macOS re-points the packet flow at a fresh utun, leaving the
/// fd passed to start on a dead interface). The client swaps its forwarding
/// device in place without dropping the QUIC connection. No-op for fd < 0.
///
/// # Safety
/// `handle` must be a live pointer returned by `masque_client_ip_start` (not
/// yet stopped).
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_update_tun_fd(
    handle: *const MasqueHandle,
    tun_fd: RawFd,
) {
    if handle.is_null() || tun_fd < 0 {
        return;
    }
    (*handle).tun_fd.replace(tun_fd);
}

/// Signal the client to reconnect immediately: with a tunnel up, it drops the
/// connection and redials at once (bypassing the QUIC idle-timeout wait — call
/// on a network path change, e.g. Wi-Fi ↔ cellular); after an `on_retry`
/// (`auto_reconnect` off), it releases the held retry. No-op if the client is
/// not running.
///
/// # Safety
/// `handle` must be a live pointer returned by `masque_client_ip_start` (not
/// yet stopped).
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_reconnect(handle: *const MasqueHandle) {
    if handle.is_null() {
        return;
    }
    (*handle).reconnect.notify_one();
}

/// Read the cumulative tunneled byte counters (survive reconnects). Either
/// out-pointer may be null.
///
/// # Safety
/// `handle` must be a live pointer returned by `masque_client_ip_start` (not
/// yet stopped); `tx_bytes` / `rx_bytes` must be valid or null.
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_stats(
    handle: *const MasqueHandle,
    tx_bytes: *mut u64,
    rx_bytes: *mut u64,
) {
    if handle.is_null() {
        return;
    }
    let h = &*handle;
    if !tx_bytes.is_null() {
        *tx_bytes = h.stats.tx.load(Ordering::Relaxed);
    }
    if !rx_bytes.is_null() {
        *rx_bytes = h.stats.rx.load(Ordering::Relaxed);
    }
}

/// Stop the client and free the handle. Safe to call once per handle.
///
/// Signals a graceful shutdown — `run` closes the active QUIC connection (so the
/// proxy releases the assigned address immediately) and returns — then joins the
/// worker thread. `run`'s shutdown path is bounded, so the join does not block.
///
/// # Safety
/// `handle` must be a pointer returned by `masque_client_ip_start`.
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_stop(handle: *mut MasqueHandle) {
    if handle.is_null() {
        return;
    }
    let mut handle = Box::from_raw(handle);
    handle.shutdown.notify_one();
    if let Some(thread) = handle.thread.take() {
        let _ = thread.join();
    }
}

fn report_error(cb: &MasqueCallbacks, msg: &str) {
    if let Ok(detail) = CString::new(msg) {
        (cb.on_state)(cb.ctx, 2, detail.as_ptr());
    }
}
