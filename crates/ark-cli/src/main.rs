use anyhow::Result;
use arkd_client::ArkClient;
use clap::{Parser, Subcommand};

/// Command-line client for arkd-rs
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
    List {
        /// Maximum number of rounds to return
        #[arg(long, default_value = "20")]
        limit: u32,
        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },
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

async fn handle_info(client: &mut ArkClient, json: bool) -> Result<()> {
    let info = client.get_info().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        println!("Server Info");
        println!("───────────────────────────────────────");
        println!("  Version:               {}", info.version);
        println!("  Network:               {}", info.network);
        println!(
            "  Signer Pubkey:         {}...",
            &info.pubkey[..16.min(info.pubkey.len())]
        );
        println!("  Session Duration:      {} blocks", info.session_duration);
        println!(
            "  Unilateral Exit Delay: {} blocks",
            info.unilateral_exit_delay
        );
        println!("  VTXO Min Amount:       {} sats", info.vtxo_min_amount);
        println!("  VTXO Max Amount:       {} sats", info.vtxo_max_amount);
        println!("  Dust:                  {} sats", info.dust);
    }
    Ok(())
}

async fn handle_round_list(
    client: &mut ArkClient,
    limit: u32,
    offset: u32,
    json: bool,
) -> Result<()> {
    let rounds = client.list_rounds(Some(limit), Some(offset)).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&rounds)?);
    } else if rounds.is_empty() {
        println!("No rounds found.");
    } else {
        println!(
            "Rounds (showing {} starting at offset {})",
            rounds.len(),
            offset
        );
        println!("───────────────────────────────────────────────────────────────");
        for round in rounds {
            let failed_marker = if round.failed { " [FAILED]" } else { "" };
            println!(
                "  {} | {} | {}{}",
                &round.id[..16.min(round.id.len())],
                round.stage,
                if round.commitment_txid.is_empty() {
                    "(no txid)".to_string()
                } else {
                    format!(
                        "{}...",
                        &round.commitment_txid[..16.min(round.commitment_txid.len())]
                    )
                },
                failed_marker
            );
        }
    }
    Ok(())
}

async fn handle_round_get(client: &mut ArkClient, round_id: &str, json: bool) -> Result<()> {
    let round = client.get_round(round_id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&round)?);
    } else {
        println!("Round Details");
        println!("───────────────────────────────────────");
        println!("  ID:              {}", round.id);
        println!("  Stage:           {}", round.stage);
        println!(
            "  Commitment TXID: {}",
            if round.commitment_txid.is_empty() {
                "(none)"
            } else {
                &round.commitment_txid
            }
        );
        println!("  Failed:          {}", round.failed);
        println!("  Intent Count:    {}", round.intent_count);
        println!("  Started:         {}", round.starting_timestamp);
        println!("  Ended:           {}", round.ending_timestamp);
    }
    Ok(())
}

async fn handle_vtxo_list(client: &mut ArkClient, pubkey: &str, json: bool) -> Result<()> {
    let vtxos = client.list_vtxos(pubkey).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&vtxos)?);
    } else if vtxos.is_empty() {
        println!("No VTXOs found for pubkey: {}", pubkey);
    } else {
        let spendable: Vec<_> = vtxos.iter().filter(|v| !v.is_spent).collect();
        let spent: Vec<_> = vtxos.iter().filter(|v| v.is_spent).collect();

        println!("VTXOs for {}...", &pubkey[..16.min(pubkey.len())]);
        println!("───────────────────────────────────────────────────────────────");

        if !spendable.is_empty() {
            println!("\n  Spendable ({}):", spendable.len());
            for vtxo in spendable {
                let swept_marker = if vtxo.is_swept { " [swept]" } else { "" };
                println!(
                    "    {}:{} — {} sats{}",
                    &vtxo.txid[..16.min(vtxo.txid.len())],
                    vtxo.vout,
                    vtxo.amount,
                    swept_marker
                );
            }
        }

        if !spent.is_empty() {
            println!("\n  Spent ({}):", spent.len());
            for vtxo in spent {
                println!(
                    "    {}:{} — {} sats",
                    &vtxo.txid[..16.min(vtxo.txid.len())],
                    vtxo.vout,
                    vtxo.amount
                );
            }
        }

        let total_spendable: u64 = vtxos.iter().filter(|v| !v.is_spent).map(|v| v.amount).sum();
        println!("\n  Total Spendable: {} sats", total_spendable);
    }
    Ok(())
}

async fn handle_command(cli: &Cli) -> Result<()> {
    let mut client = ArkClient::new(&cli.server);

    // Commands that require connection
    let needs_connection = !matches!(cli.command, Commands::Receive);

    if needs_connection {
        client
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to {}: {}", cli.server, e))?;
    }

    match &cli.command {
        Commands::Info => handle_info(&mut client, cli.json).await?,
        Commands::Status => handle_info(&mut client, cli.json).await?,
        Commands::Round { action } => match action {
            RoundAction::List { limit, offset } => {
                handle_round_list(&mut client, *limit, *offset, cli.json).await?
            }
            RoundAction::Get { id } => handle_round_get(&mut client, id, cli.json).await?,
        },
        Commands::Vtxo { action } => match action {
            VtxoAction::List { pubkey } => handle_vtxo_list(&mut client, pubkey, cli.json).await?,
        },
        Commands::ListVtxos { pubkey } => {
            if let Some(pk) = pubkey {
                handle_vtxo_list(&mut client, pk, cli.json).await?
            } else if cli.json {
                let out = serde_json::json!({
                    "error": "pubkey required",
                    "hint": "Use --pubkey <PUBKEY> to specify which pubkey to query"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Error: pubkey required. Use --pubkey <PUBKEY>");
            }
        }
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
                    "status": "not_implemented",
                    "note": "Boarding RPC requires RegisterForRound + confirmation flow"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Board command not yet implemented.");
                println!("Boarding requires the full RegisterForRound + confirmation flow.");
                println!(
                    "Would register UTXO {}:{} ({} sats) for pubkey {}",
                    txid, vout, amount, pubkey
                );
            }
        }
        Commands::Send { to, amount } => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "send",
                    "to": to,
                    "amount": amount,
                    "status": "not_implemented",
                    "note": "Send requires SubmitTx + FinalizeTx flow"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Send command not yet implemented.");
                println!("Sending requires the SubmitTx + FinalizeTx flow.");
                println!("Would transfer {} sats to {}", amount, to);
            }
        }
        Commands::Receive => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "receive",
                    "status": "not_implemented",
                    "note": "Local wallet/key management not yet implemented"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Receive command not yet implemented.");
                println!("This requires local wallet/key management.");
            }
        }
        Commands::Exit { vtxo_id } => {
            if cli.json {
                let out = serde_json::json!({
                    "command": "exit",
                    "vtxo_id": vtxo_id,
                    "status": "not_implemented",
                    "note": "Exit requires RequestExit RPC + transaction signing"
                });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("Exit command not yet implemented.");
                println!("Unilateral exit requires RequestExit RPC + transaction signing.");
                println!("Would initiate exit for VTXO {}", vtxo_id);
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if let Err(e) = handle_command(&cli).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

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
                action: RoundAction::List { .. }
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
    fn test_cli_round_list_with_limit() {
        let cli = Cli::parse_from(["ark-cli", "round", "list", "--limit", "50"]);
        if let Commands::Round {
            action: RoundAction::List { limit, offset },
        } = &cli.command
        {
            assert_eq!(*limit, 50);
            assert_eq!(*offset, 0);
        } else {
            panic!("Expected Round List command");
        }
    }

    #[test]
    fn test_cli_help_does_not_panic() {
        let result = Cli::try_parse_from(["ark-cli", "--help"]);
        assert!(result.is_err());
    }
}
