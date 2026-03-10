use anyhow::Result;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("Starting arkd-rs - Ark protocol server (Rust)");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // TODO: Load configuration
    // TODO: Initialize database
    // TODO: Start gRPC server
    // TODO: Start wallet service

    info!("Server initialization complete");
    info!("Listening on port 7070 (gRPC)");

    // Keep server running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down gracefully...");

    Ok(())
}
