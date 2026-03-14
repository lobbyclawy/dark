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
    /// Register an on-chain UTXO as a VTXO (boarding)
    Board {
        /// Transaction ID of the on-chain UTXO
        txid: String,
        /// Output index
        vout: u32,
        /// Amount in satoshis
        amount: u64,
        /// Receiver pubkey (hex)
        pubkey: String,
    },
    /// Send VTXOs to a recipient
    Send {
        /// Recipient pubkey (hex)
        to: String,
        /// Amount in satoshis
        amount: u64,
    },
    /// Show receive pubkey/address
    Receive,
    /// List all VTXOs for this wallet
    ListVtxos {
        /// Filter by pubkey (optional)
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Unilateral exit to on-chain
    Exit {
        /// VTXO ID to exit
        vtxo_id: String,
    },
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
        Commands::Board {
            txid,
            vout,
            amount,
            pubkey,
        } => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "board",
                    "txid": txid,
                    "vout": vout,
                    "amount": amount,
                    "pubkey": pubkey,
                    "server": cli.server,
                    "note": "stub — gRPC client TODO"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Board: would register UTXO {}:{} ({} sats) for pubkey {} via {}",
                    txid, vout, amount, pubkey, cli.server
                );
            }
        }
        Commands::Send { to, amount } => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "send",
                    "to": to,
                    "amount": amount,
                    "server": cli.server,
                    "note": "stub — gRPC client TODO"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Send: would transfer {} sats to {} via {}",
                    amount, to, cli.server
                );
            }
        }
        Commands::Receive => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "receive",
                    "server": cli.server,
                    "note": "stub — gRPC client TODO"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Receive: would return pubkey/address for {} — gRPC not yet wired",
                    cli.server
                );
            }
        }
        Commands::ListVtxos { pubkey } => {
            let filter = pubkey.as_deref().unwrap_or("(all)");
            if cli.json {
                let out = serde_json::json!({
                    "command": "list-vtxos",
                    "pubkey_filter": filter,
                    "vtxos": [],
                    "server": cli.server,
                    "note": "stub — gRPC client TODO"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "ListVtxos: would list VTXOs for pubkey={} via {}",
                    filter, cli.server
                );
            }
        }
        Commands::Exit { vtxo_id } => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "exit",
                    "vtxo_id": vtxo_id,
                    "server": cli.server,
                    "note": "stub — gRPC client TODO"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!(
                    "Exit: would initiate unilateral exit for VTXO {} via {}",
                    vtxo_id, cli.server
                );
            }
        }
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
    fn test_cli_board_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "board", "abc123", "0", "100000", "02deadbeef"]);
        assert!(matches!(cli.command, Commands::Board { .. }));
    }

    #[test]
    fn test_cli_send_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "send", "02deadbeef", "50000"]);
        assert!(matches!(cli.command, Commands::Send { .. }));
    }

    #[test]
    fn test_cli_receive_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "receive"]);
        assert!(matches!(cli.command, Commands::Receive));
    }

    #[test]
    fn test_cli_list_vtxos_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "list-vtxos"]);
        assert!(matches!(cli.command, Commands::ListVtxos { .. }));
    }

    #[test]
    fn test_cli_list_vtxos_with_pubkey_filter() {
        let cli = Cli::parse_from(["ark-cli", "list-vtxos", "--pubkey", "02abc"]);
        if let Commands::ListVtxos { pubkey } = &cli.command {
            assert_eq!(pubkey.as_deref(), Some("02abc"));
        } else {
            panic!("Expected ListVtxos command");
        }
    }

    #[test]
    fn test_cli_exit_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "exit", "vtxo-id-123"]);
        assert!(matches!(cli.command, Commands::Exit { .. }));
    }

    #[test]
    fn test_cli_help_does_not_panic() {
        // Verify the CLI can be built without panicking
        let result = Cli::try_parse_from(["ark-cli", "--help"]);
        // --help causes an early exit / error, but should not panic
        assert!(result.is_err());
    }
}
