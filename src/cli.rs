use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "dark", about = "Ark protocol server (Rust)")]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml", env = "DARK_CONFIG")]
    pub config: String,

    /// Override gRPC listen address
    #[arg(long)]
    pub grpc_addr: Option<String>,

    /// Override gRPC listen port (ignored if --grpc-addr is set)
    #[arg(long)]
    pub grpc_port: Option<u16>,

    /// Override admin gRPC listen port
    #[arg(long)]
    pub admin_port: Option<u16>,

    /// Override log level (trace/debug/info/warn/error)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
