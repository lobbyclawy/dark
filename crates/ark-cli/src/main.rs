use anyhow::Result;
use clap::{Parser, Subcommand};

/// Command-line client for testing arkd-rs interactively
#[derive(Parser, Debug)]
#[command(name = "ark-cli", version, about)]
pub struct Cli {
    /// Server URL to connect to
    #[arg(long, default_value = "http://localhost:50051", global = true)]
    pub server: String,

    /// Output results as JSON
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show server info
    Info,
    /// Round management commands
    Round {
        #[command(subcommand)]
        action: RoundAction,
    },
    /// VTXO management commands
    Vtxo {
        #[command(subcommand)]
        action: VtxoAction,
    },
    /// Show server status
    Status,
}

#[derive(Subcommand, Debug)]
pub enum RoundAction {
    /// List all rounds
    List,
    /// Get details for a specific round
    Get {
        /// Round identifier
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum VtxoAction {
    /// List VTXOs for a public key
    List {
        /// Public key to query
        pubkey: String,
    },
}

fn handle_command(cli: &Cli) -> Result<()> {
    match &cli.command {
        Commands::Info => {
            if cli.json {
                let info = serde_json::json!({
                    "server": cli.server,
                    "grpc_client": "TODO — gRPC client not yet implemented",
                });
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("Server: {}", cli.server);
                println!("gRPC client: TODO — not yet implemented");
            }
        }
        Commands::Round { action } => match action {
            RoundAction::List => {
                if cli.json {
                    let out =
                        serde_json::json!({ "rounds": [], "note": "stub — gRPC client TODO" });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("[stub] Would list rounds from {}", cli.server);
                }
            }
            RoundAction::Get { id } => {
                if cli.json {
                    let out =
                        serde_json::json!({ "round_id": id, "note": "stub — gRPC client TODO" });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("[stub] Would get round {} from {}", id, cli.server);
                }
            }
        },
        Commands::Vtxo { action } => match action {
            VtxoAction::List { pubkey } => {
                if cli.json {
                    let out = serde_json::json!({ "pubkey": pubkey, "vtxos": [], "note": "stub — gRPC client TODO" });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("[stub] Would list VTXOs for {} from {}", pubkey, cli.server);
                }
            }
        },
        Commands::Status => {
            if cli.json {
                let out = serde_json::json!({ "server": cli.server, "status": "unknown", "note": "stub — gRPC client TODO" });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("[stub] Would check status of {}", cli.server);
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    handle_command(&cli)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_info_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "info"]);
        assert!(matches!(cli.command, Commands::Info));
    }

    #[test]
    fn test_cli_round_list_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "round", "list"]);
        assert!(matches!(
            cli.command,
            Commands::Round {
                action: RoundAction::List
            }
        ));
    }

    #[test]
    fn test_cli_default_server() {
        let cli = Cli::parse_from(["ark-cli", "info"]);
        assert_eq!(cli.server, "http://localhost:50051");
    }

    #[test]
    fn test_cli_json_flag() {
        let cli = Cli::parse_from(["ark-cli", "--json", "info"]);
        assert!(cli.json);
    }

    #[test]
    fn test_cli_help_does_not_panic() {
        // Verify the CLI can be built without panicking
        let result = Cli::try_parse_from(["ark-cli", "--help"]);
        // --help causes an early exit / error, but should not panic
        assert!(result.is_err());
    }
}
