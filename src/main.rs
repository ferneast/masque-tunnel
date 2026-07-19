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
    about = "MASQUE tunnel: CONNECT-UDP (RFC 9298) and CONNECT-IP (RFC 9484)",
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

        /// Enable CONNECT-IP: IPv4 pool in CIDR notation (e.g. 10.99.0.0/24).
        /// Requires root for the TUN device; enable IP forwarding + NAT for
        /// internet-bound traffic
        #[arg(long)]
        ip_pool: Option<String>,

        /// Enable CONNECT-IP IPv6: IPv6 pool in CIDR notation (e.g.
        /// 2001:db8:1::/64). Can be combined with --ip-pool for dual-stack
        #[arg(long)]
        ip6_pool: Option<String>,

        /// MTU of the server-side CONNECT-IP TUN device
        #[arg(long, default_value_t = 1280)]
        ip_mtu: u16,

        /// Name for the server-side CONNECT-IP TUN device
        #[arg(long)]
        ip_tun_name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = log::set_logger(&STDERR_LOGGER);
    log::set_max_level(log::LevelFilter::Info);

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
        } => {
            ip_client::run(ip_client::IpClientConfig {
                proxy_url,
                sni,
                auth_token,
                insecure,
                ca,
                mtu,
                tun_name,
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
            })
            .await
        }
    }
}
