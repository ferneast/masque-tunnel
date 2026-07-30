use clap::{Parser, Subcommand};
use masque_tunnel::{client, ip_client, server};

/// Minimal stderr logger.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "[{}] {}",
                record.level().as_str().to_lowercase(),
                record.args()
            );
        }
    }
    fn flush(&self) {}
}

static STDERR_LOGGER: StderrLogger = StderrLogger;

#[derive(Parser)]
#[command(
    name = "masque-tunnel",
    about = "MASQUE CONNECT-UDP tunnel (RFC 9298)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as MASQUE CONNECT-UDP client
    Client {
        /// Local UDP address to listen on (e.g. 127.0.0.1:51820)
        #[arg(long, short)]
        listen: String,

        /// MASQUE proxy server URL (e.g. https://proxy.example.com:443)
        #[arg(long, short)]
        proxy_url: String,

        /// Target UDP endpoint (e.g. 10.0.0.1:51820)
        #[arg(long, short)]
        target: String,

        /// TLS server name (SNI) override
        #[arg(long)]
        sni: Option<String>,

        /// Bearer token for Proxy-Authorization header
        #[arg(long)]
        auth_token: Option<String>,

        /// CA certificate PEM file for server verification. Omit to use the
        /// Mozilla CA bundle, which trusts public ACME certificates.
        #[arg(long)]
        ca: Option<String>,

        /// Skip server certificate verification
        #[arg(long)]
        insecure: bool,
    },

    /// Run as MASQUE CONNECT-IP client: a full-tunnel VPN over a local TUN
    /// device (requires root to create the TUN)
    ClientIp {
        /// MASQUE proxy server URL (e.g. https://proxy.example.com:443)
        #[arg(long, short)]
        proxy_url: String,

        /// TLS server name (SNI) override
        #[arg(long)]
        sni: Option<String>,

        /// Bearer token for Proxy-Authorization header
        #[arg(long)]
        auth_token: Option<String>,

        /// CA certificate PEM file for server verification
        #[arg(long)]
        ca: Option<String>,

        /// Skip server certificate verification
        #[arg(long)]
        insecure: bool,

        /// TUN device MTU; must fit in a QUIC DATAGRAM on the proxy path
        #[arg(long, default_value_t = 1280)]
        mtu: u16,

        /// TUN device name (Linux: any; macOS: utunN or omit for automatic)
        #[arg(long)]
        tun_name: Option<String>,

        /// Take over the host's default route when the proxy advertises a full
        /// tunnel (0.0.0.0/0 or ::/0): pins the proxy address to the real
        /// gateway and installs a split default. Reverted on exit (Ctrl-C).
        #[arg(long)]
        redirect_gateway: bool,

        /// Set the system DNS resolver(s) while the tunnel is up (repeatable),
        /// restored on exit. Independent of --redirect-gateway; logs a leak
        /// warning if the resolver is not routed through the tunnel.
        #[arg(long)]
        dns: Vec<std::net::IpAddr>,

        /// Preferred tunnel address to request on a cold start, before any
        /// address is assigned (e.g. 10.99.0.2). Repeatable to prefer one per
        /// family; the first entry of each family is used. Omit for the default
        /// all-zero "no preference" request. A held address (kept across
        /// reconnects) always takes precedence over this hint.
        #[arg(long)]
        preferred_address: Vec<std::net::IpAddr>,
    },

    /// Run as MASQUE proxy server (CONNECT-UDP always; CONNECT-IP with --ip-pool)
    Server {
        /// Address to listen on (e.g. [::]:443)
        #[arg(long, short, default_value = "[::]:443")]
        listen: String,

        /// TLS certificate PEM file
        #[arg(long)]
        cert: String,

        /// TLS private key PEM file
        #[arg(long)]
        key: String,

        /// Required Bearer token for client authentication
        #[arg(long)]
        auth_token: Option<String>,

        /// Enable CONNECT-IP (RFC 9484) with this IPv4 pool (CIDR, e.g. 10.99.0.0/24)
        #[arg(long)]
        ip_pool: Option<String>,

        /// Enable CONNECT-IP with this IPv6 pool (CIDR, e.g. 2001:db8:1::/64)
        #[arg(long)]
        ip6_pool: Option<String>,

        /// MTU of the CONNECT-IP TUN device
        #[arg(long, default_value_t = 1280)]
        ip_mtu: u16,

        /// Name for the CONNECT-IP TUN device (Linux: any; macOS: utunN)
        #[arg(long)]
        ip_tun_name: Option<String>,

        /// File of routes to advertise to CONNECT-IP clients: one CIDR per
        /// line (# comments and blank lines ignored), IPv4/IPv6 mixed. Clients
        /// route only these prefixes through the tunnel (split tunnel). Omit to
        /// advertise a full tunnel (0.0.0.0/0 and/or ::/0).
        #[arg(long)]
        ip_routes_file: Option<String>,

        /// DNS resolver(s) to advertise to CONNECT-IP clients via a DNS_ASSIGN
        /// capsule (draft-ietf-masque-connect-ip-dns), repeatable. Clients
        /// without their own --dns adopt these automatically.
        #[arg(long)]
        dns_assign: Vec<std::net::IpAddr>,

        /// Allow CONNECT-IP clients to reach private destinations behind the
        /// server (RFC 1918, CGN 100.64.0.0/10, IPv6 ULA), e.g. for LAN
        /// access. Loopback, link-local (cloud metadata), multicast, and
        /// broadcast destinations are always dropped. The tunnel's own pool
        /// and --dns-assign resolvers are always reachable.
        #[arg(long)]
        ip_allow_private: bool,

        /// Serve this directory to every request that is not an authenticated
        /// tunnel session, so an active prober sees a website rather than a
        /// proxy. index.html is used for directory paths. Without this or
        /// --masquerade-url, a built-in placeholder page is served.
        #[arg(long)]
        masquerade_dir: Option<String>,

        /// Redirect (302) every non-tunnel request to this absolute URL,
        /// instead of serving local files. Conflicts with --masquerade-dir.
        #[arg(long, conflicts_with = "masquerade_dir")]
        masquerade_url: Option<String>,

        /// Value for the `Server` response header, e.g. "nginx". Sent on decoy
        /// and tunnel responses alike so neither can be told from the other.
        /// Omit to send no Server header at all.
        #[arg(long)]
        server_header: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = log::set_logger(&STDERR_LOGGER);
    // Honor RUST_LOG as a plain level name (e.g. trace) so quinn/h3 internals
    // can be inspected without a rebuild; default to Info.
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<log::LevelFilter>().ok())
        .unwrap_or(log::LevelFilter::Info);
    log::set_max_level(level);

    let cli = Cli::parse();

    match cli.command {
        Commands::Client {
            listen,
            proxy_url,
            target,
            sni,
            auth_token,
            insecure,
            ca,
        } => {
            client::run(client::ClientConfig {
                listen,
                proxy_url,
                target,
                sni,
                auth_token,
                insecure,
                ca,
            })
            .await
        }
        Commands::ClientIp {
            proxy_url,
            sni,
            auth_token,
            ca,
            insecure,
            mtu,
            tun_name,
            redirect_gateway,
            dns,
            preferred_address,
        } => {
            ip_client::run(ip_client::IpClientConfig {
                proxy_url,
                sni,
                auth_token,
                insecure,
                ca,
                mtu,
                tun_name,
                redirect_gateway,
                dns,
                tun_fd: None,
                events: None,
                stats: None,
                reconnect: None,
                shutdown: None,
                preferred_addresses: preferred_address,
                auto_reconnect: true,
            })
            .await
        }
        Commands::Server {
            listen,
            cert,
            key,
            auth_token,
            ip_pool,
            ip6_pool,
            ip_mtu,
            ip_tun_name,
            ip_routes_file,
            dns_assign,
            ip_allow_private,
            masquerade_dir,
            masquerade_url,
            server_header,
        } => {
            server::run(server::ServerConfig {
                listen,
                cert,
                key,
                auth_token,
                ip_pool,
                ip6_pool,
                ip_mtu,
                ip_tun_name,
                ip_routes_file,
                dns_assign,
                ip_allow_private,
                masquerade_dir,
                masquerade_url,
                server_header,
            })
            .await
        }
    }
}
