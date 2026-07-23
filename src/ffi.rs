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

use tokio::sync::oneshot;

use crate::capsule::IpAddressRange;
use crate::ip_client::{self, ClientEvents, IpClientConfig, TunnelStats};

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

/// Opaque handle owning the worker thread, its shutdown channel, and the
/// traffic counters.
pub struct MasqueHandle {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    stats: Arc<TunnelStats>,
}

unsafe fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(str::to_owned)
}

/// Start the CONNECT-IP client against `proxy_url`, forwarding over `tun_fd`
/// (a dup of the provider's utun fd). `auth_token` and `sni` may be null;
/// `mtu` 0 selects the default (1280). Returns an opaque handle, or null on
/// invalid input.
///
/// # Safety
/// `proxy_url` must be a valid NUL-terminated UTF-8 string; `auth_token` and
/// `sni` the same or null. `callbacks` pointers must remain valid until stop.
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_start(
    proxy_url: *const c_char,
    auth_token: *const c_char,
    sni: *const c_char,
    insecure: bool,
    mtu: u16,
    tun_fd: RawFd,
    callbacks: MasqueCallbacks,
) -> *mut MasqueHandle {
    let Some(proxy_url) = cstr(proxy_url) else {
        return std::ptr::null_mut();
    };
    let auth_token = cstr(auth_token);
    let sni = cstr(sni);
    let stats = Arc::new(TunnelStats::default());

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
        tun_fd: Some(tun_fd),
        events: Some(Arc::new(HostEvents { cb: callbacks })),
        stats: Some(stats.clone()),
    };

    let (tx, rx) = oneshot::channel::<()>();
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
            tokio::select! {
                // `run` loops forever reconnecting; it only returns on a fatal
                // setup error, which we surface to the host.
                res = ip_client::run(config) => {
                    if let Err(e) = res {
                        report_error(&callbacks, &e.to_string());
                    }
                }
                _ = rx => {} // stop requested: drop the tunnel future, cleaning up
            }
        });
    });

    Box::into_raw(Box::new(MasqueHandle {
        shutdown: Some(tx),
        thread: Some(thread),
        stats,
    }))
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
/// # Safety
/// `handle` must be a pointer returned by `masque_client_ip_start`.
#[no_mangle]
pub unsafe extern "C" fn masque_client_ip_stop(handle: *mut MasqueHandle) {
    if handle.is_null() {
        return;
    }
    let mut handle = Box::from_raw(handle);
    if let Some(tx) = handle.shutdown.take() {
        let _ = tx.send(());
    }
    if let Some(thread) = handle.thread.take() {
        let _ = thread.join();
    }
}

fn report_error(cb: &MasqueCallbacks, msg: &str) {
    if let Ok(detail) = CString::new(msg) {
        (cb.on_state)(cb.ctx, 2, detail.as_ptr());
    }
}
