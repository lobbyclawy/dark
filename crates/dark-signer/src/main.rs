//! dark-signer — standalone gRPC signer for ASP key isolation.
//!
//! Implements `SignerService` (signer_service.proto) so the main dark
//! process never touches the private key directly.

mod service;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tonic::transport::Server;
use tracing::{info, warn};

use dark_api::proto::ark_v1::signer_service_server::SignerServiceServer;
use service::SignerServiceImpl;

/// Standalone signer binary for dark key isolation.
#[derive(Parser, Debug)]
#[command(name = "dark-signer", version, about)]
struct Cli {
    /// Path to a file containing the 32-byte hex-encoded private key.
    #[arg(long, env = "DARK_SIGNER_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Hex-encoded private key (prefer --key-file or env for production).
    #[arg(long, env = "DARK_SIGNER_KEY_HEX", hide = true)]
    key_hex: Option<String>,

    /// gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:7070", env = "DARK_SIGNER_LISTEN")]
    listen_addr: SocketAddr,

    /// Bitcoin network (bitcoin, testnet, signet, regtest).
    #[arg(long, default_value = "bitcoin", env = "DARK_SIGNER_NETWORK")]
    network: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Resolve the private key.
    let key_hex = match (&cli.key_file, &cli.key_hex) {
        (Some(path), _) => {
            info!(path = %path.display(), "Loading private key from file");
            std::fs::read_to_string(path)
                .with_context(|| format!("reading key file {}", path.display()))?
                .trim()
                .to_string()
        }
        (None, Some(hex)) => {
            warn!("Private key supplied via CLI arg / env var — use --key-file in production");
            hex.clone()
        }
        (None, None) => {
            anyhow::bail!(
                "No private key provided. Use --key-file <path> or --key-hex / DARK_SIGNER_KEY_HEX"
            );
        }
    };

    let network: bitcoin::Network = cli
        .network
        .parse()
        .with_context(|| format!("invalid network '{}'", cli.network))?;

    let signer = SignerServiceImpl::from_hex(&key_hex, network)
        .map_err(|e| anyhow::anyhow!("failed to initialise signer from provided key: {e}"))?;

    let pubkey = signer.public_key_hex();
    info!(
        listen = %cli.listen_addr,
        network = %cli.network,
        pubkey = %pubkey,
        "dark-signer starting"
    );

    Server::builder()
        .add_service(SignerServiceServer::new(signer))
        .serve(cli.listen_addr)
        .await
        .context("gRPC server error")?;

    Ok(())
}
