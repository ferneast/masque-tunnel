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

        /// CA certificate PEM file for server verification
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
            })
            .await
        }
    }
}
