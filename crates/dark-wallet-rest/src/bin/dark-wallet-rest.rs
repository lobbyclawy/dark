//! `dark-wallet-rest` binary — launches the REST wallet daemon.

use std::net::SocketAddr;

use clap::Parser;
use dark_wallet_rest::{config, Config, RestServer};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "dark-wallet-rest",
    about = "REST wallet daemon for dark (axum + utoipa on top of dark-client)"
)]
struct Cli {
    /// HTTP listen address.
    #[arg(long, env = "DARK_REST_LISTEN", default_value = "127.0.0.1:7072")]
    listen_addr: SocketAddr,

    /// URL of the upstream dark gRPC server.
    #[arg(long, env = "DARK_GRPC_URL", default_value = "http://localhost:7070")]
    dark_grpc_url: String,

    /// Disable bearer-token authentication on /v1 routes (dev only).
    #[arg(long, env = "DARK_REST_AUTH_DISABLED")]
    auth_disabled: bool,

    /// Macaroon root key — either a hex string or `@/path/to/file`.
    /// Required unless `--auth-disabled` is set.
    #[arg(long, env = "DARK_MACAROON_ROOT_KEY")]
    macaroon_root_key: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let macaroon_root_key = config::load_root_key(cli.macaroon_root_key.as_deref())?;

    if !cli.auth_disabled && macaroon_root_key.is_none() {
        anyhow::bail!(
            "auth is enabled but no macaroon root key configured; pass \
             --macaroon-root-key <hex|@path> or --auth-disabled"
        );
    }

    let config = Config {
        listen_addr: cli.listen_addr,
        dark_grpc_url: cli.dark_grpc_url,
        auth_disabled: cli.auth_disabled,
        macaroon_root_key,
    };

    let server = RestServer::start(&config).await?;

    tokio::signal::ctrl_c().await?;
    server.stop_wait().await
}
