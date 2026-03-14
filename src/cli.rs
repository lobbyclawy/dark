use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "arkd", about = "Ark protocol server (Rust)")]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml", env = "ARKD_CONFIG")]
    pub config: String,

    /// Override gRPC listen address
    #[arg(long)]
    pub grpc_addr: Option<String>,

    /// Override log level (trace/debug/info/warn/error)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
