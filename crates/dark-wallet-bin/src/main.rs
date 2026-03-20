//! dark-wallet-bin — standalone gRPC wallet server for dark.
//!
//! Exposes a subset of the Go dark-wallet RPCs with AES-256-GCM seed encryption,
//! PBKDF2 key derivation, and BDK integration via the `dark-wallet` library crate.

mod encryption;
mod grpc_service;

/// Generated protobuf/gRPC types for `ark.v1.WalletService`.
mod proto {
    tonic::include_proto!("ark.v1");
}

use std::net::SocketAddr;
use std::path::PathBuf;

use bitcoin::Network;
use clap::Parser;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use grpc_service::WalletGrpcService;
use proto::wallet_service_server::WalletServiceServer;

#[derive(Parser, Debug)]
#[command(name = "dark-wallet-bin", about = "Standalone gRPC wallet for dark")]
struct Cli {
    /// gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:9111")]
    listen_addr: SocketAddr,

    /// Bitcoin network (bitcoin, testnet, signet, regtest).
    #[arg(long, default_value = "regtest")]
    network: String,

    /// Data directory for wallet database and encrypted seed.
    #[arg(long, default_value = "./wallet-data")]
    data_dir: PathBuf,

    /// Esplora API URL for blockchain data.
    #[arg(long, default_value = "http://localhost:3002")]
    esplora_url: String,
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(Network::Bitcoin),
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!("unknown network: {other}")),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let cli = Cli::parse();
    let network =
        parse_network(&cli.network).map_err(|e| anyhow::anyhow!("invalid network: {e}"))?;

    info!(
        listen = %cli.listen_addr,
        network = %cli.network,
        data_dir = %cli.data_dir.display(),
        esplora = %cli.esplora_url,
        "Starting dark-wallet-bin"
    );

    // Ensure data directory exists.
    std::fs::create_dir_all(&cli.data_dir)?;

    let service = WalletGrpcService::new(cli.data_dir, network, cli.esplora_url);

    Server::builder()
        .add_service(WalletServiceServer::new(service))
        .serve(cli.listen_addr)
        .await?;

    Ok(())
}
