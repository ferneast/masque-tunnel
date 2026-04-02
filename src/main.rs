use clap::{Parser, Subcommand};
use masque_tunnel::{client, server};

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

    /// Run as MASQUE CONNECT-UDP proxy server
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
        Commands::Server {
            listen,
            cert,
            key,
            auth_token,
        } => {
            server::run(server::ServerConfig {
                listen,
                cert,
                key,
                auth_token,
            })
            .await
        }
    }
}
