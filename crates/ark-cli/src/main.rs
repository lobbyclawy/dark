mod confidential;
mod confidential_tx_stub;
mod disclose;
mod stealth;
mod wallet_config;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use confidential::SendArgs;
use dark_client::ArkClient;
use disclose::{DiscloseArgs, VerifyArgs};
use stealth::StealthAction;
use wallet_config::{load as load_config, resolve_config_path};

/// Command-line client for dark.
///
/// # Confidential VTXOs
///
/// To send to a stealth meta-address run:
///
/// ```text
/// ark-cli send --to <meta-address> --amount <sats> [--confidential] [--memo <text>]
/// ```
///
/// `--confidential` is implicit when the wallet has been configured
/// with `default_confidential = true`. Print your own meta-address
/// with `ark-cli receive`, and pull newly delivered VTXOs with
/// `ark-cli scan`.
#[derive(Parser, Debug)]
#[command(name = "ark-cli", version, about)]
pub struct Cli {
    /// Server URL to connect to.
    #[arg(long, default_value = "http://localhost:50051", global = true)]
    pub server: String,

    /// Output results as JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// Path to the wallet config file. Defaults to
    /// `$XDG_CONFIG_HOME/ark-cli/config.toml`.
    #[arg(long, global = true, value_name = "PATH")]
    pub config_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show server info.
    Info,
    /// Round management commands.
    Round {
        #[command(subcommand)]
        action: RoundAction,
    },
    /// VTXO management commands.
    Vtxo {
        #[command(subcommand)]
        action: VtxoAction,
    },
    /// Show server status.
    Status,
    /// Register an on-chain UTXO as a VTXO (boarding).
    Board {
        /// Transaction ID of the on-chain UTXO.
        txid: String,
        /// Output index.
        vout: u32,
        /// Amount in satoshis.
        amount: u64,
        /// Receiver pubkey (hex).
        pubkey: String,
    },
    /// Send VTXOs to a recipient.
    ///
    /// Pass a meta-address (`darks1…` / `tdarks1…` / `rdarks1…`) with
    /// `--to` to issue a confidential transfer. The `--confidential`
    /// flag is implied when the wallet config sets
    /// `default_confidential = true`; pass `--no-confidential` to opt
    /// out for a single send.
    Send(SendArgs),
    /// Print the wallet's stealth meta-address for receiving
    /// confidential VTXOs.
    Receive,
    /// Run a one-shot stealth scan and print discovered VTXOs.
    Scan,
    /// View or update the wallet config (toggles `default_confidential`,
    /// `seed`, `network`).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// List all VTXOs for this wallet.
    ListVtxos {
        /// Filter by pubkey (optional).
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Unilateral exit to on-chain.
    Exit {
        /// VTXO ID to exit.
        vtxo_id: String,
    },
    /// Stealth meta-address commands (encode, decode, show wallet address).
    Stealth {
        #[command(subcommand)]
        action: StealthAction,
    },
    /// Assemble a compliance bundle for a VTXO.
    ///
    /// Pick one or more disclosure types: `--selective-reveal`,
    /// `--lower`/`--upper` (bounded range), `--source-of-funds <root>`.
    Disclose(DiscloseArgs),
    /// Verify every proof in a compliance bundle.
    ///
    /// Reads from `--in <path>` or stdin and exits non-zero if any
    /// contained proof fails to verify.
    Verify(VerifyArgs),
}

#[derive(Subcommand, Debug)]
pub enum RoundAction {
    /// List all rounds.
    List {
        /// Maximum number of rounds to return.
        #[arg(long, default_value = "20")]
        limit: u32,
        /// Offset for pagination.
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Get details for a specific round.
    Get {
        /// Round identifier.
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum VtxoAction {
    /// List VTXOs for a public key.
    List {
        /// Public key to query.
        pubkey: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Set a config value (e.g. `set default_confidential true`).
    Set {
        /// Config key (`default_confidential` | `seed` | `network`).
        key: String,
        /// New value.
        value: String,
    },
    /// Print the current value of a config key.
    Get {
        /// Config key (`default_confidential` | `seed` | `network`).
        key: String,
    },
    /// Print the resolved config file path.
    Path,
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

/// Commands that talk only to local state (config, key derivation,
/// disclosure files) — they MUST NOT open a gRPC connection.
fn is_local_only(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Receive
            | Commands::Stealth { .. }
            | Commands::Config { .. }
            | Commands::Disclose(_)
            | Commands::Verify(_)
            | Commands::Send(_) // send routes through the stub for now
    )
}

async fn handle_command(cli: &Cli) -> Result<()> {
    let mut client = ArkClient::new(&cli.server);

    if !is_local_only(&cli.command) {
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
        Commands::Send(args) => {
            let config = load_wallet_config(cli)?;
            confidential::handle_send(args, &config, cli.json)?;
        }
        Commands::Receive => {
            let config = load_wallet_config(cli)?;
            confidential::handle_receive(&config, cli.json)?;
        }
        Commands::Scan => {
            let config = load_wallet_config(cli)?;
            // `client` was already connected above (Scan is not
            // local-only). Hand it to the scanner — it owns it for
            // the duration of the call.
            confidential::handle_scan(client, &config, cli.json).await?;
        }
        Commands::Config { action } => handle_config_command(cli, action)?,
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
        Commands::Stealth { action } => stealth::handle(action, cli.json)?,
        Commands::Disclose(args) => disclose::handle_disclose(args)?,
        Commands::Verify(args) => disclose::handle_verify(args)?,
    }
    Ok(())
}

fn load_wallet_config(cli: &Cli) -> Result<wallet_config::WalletConfig> {
    let path = resolve_config_path(cli.config_path.as_deref())?;
    load_config(&path)
}

fn handle_config_command(cli: &Cli, action: &ConfigAction) -> Result<()> {
    let path = resolve_config_path(cli.config_path.as_deref())?;
    match action {
        ConfigAction::Set { key, value } => {
            let mut config = load_config(&path)?;
            confidential::handle_config_set(&path, &mut config, key, value, cli.json)
        }
        ConfigAction::Get { key } => {
            let config = load_config(&path)?;
            confidential::handle_config_get(&config, key, cli.json)
        }
        ConfigAction::Path => {
            if cli.json {
                let out = serde_json::json!({ "path": path.display().to_string() });
                println!("{}", serde_json::to_string_pretty(&out)?);
            } else {
                println!("{}", path.display());
            }
            Ok(())
        }
    }
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
    fn test_cli_send_command_parses_meta_address() {
        let cli = Cli::parse_from(["ark-cli", "send", "--to", "darks1xyz", "--amount", "50000"]);
        match cli.command {
            Commands::Send(args) => {
                assert_eq!(args.to, "darks1xyz");
                assert_eq!(args.amount, 50_000);
                assert!(!args.confidential);
                assert!(!args.no_confidential);
                assert!(args.memo.is_none());
            }
            _ => panic!("expected Send command"),
        }
    }

    #[test]
    fn test_cli_send_command_accepts_confidential_and_memo_flags() {
        let cli = Cli::parse_from([
            "ark-cli",
            "send",
            "--to",
            "darks1xyz",
            "--amount",
            "50000",
            "--confidential",
            "--memo",
            "lunch",
        ]);
        match cli.command {
            Commands::Send(args) => {
                assert!(args.confidential);
                assert_eq!(args.memo.as_deref(), Some("lunch"));
            }
            _ => panic!("expected Send command"),
        }
    }

    #[test]
    fn test_cli_send_rejects_conflicting_confidential_flags() {
        let result = Cli::try_parse_from([
            "ark-cli",
            "send",
            "--to",
            "darks1xyz",
            "--amount",
            "100",
            "--confidential",
            "--no-confidential",
        ]);
        assert!(
            result.is_err(),
            "--confidential and --no-confidential must conflict"
        );
    }

    #[test]
    fn test_cli_receive_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "receive"]);
        assert!(matches!(cli.command, Commands::Receive));
    }

    #[test]
    fn test_cli_scan_command_exists() {
        let cli = Cli::parse_from(["ark-cli", "scan"]);
        assert!(matches!(cli.command, Commands::Scan));
    }

    #[test]
    fn test_cli_config_set_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "config", "set", "default_confidential", "true"]);
        match cli.command {
            Commands::Config {
                action: ConfigAction::Set { key, value },
            } => {
                assert_eq!(key, "default_confidential");
                assert_eq!(value, "true");
            }
            _ => panic!("expected Config Set command"),
        }
    }

    #[test]
    fn test_cli_config_get_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "config", "get", "network"]);
        match cli.command {
            Commands::Config {
                action: ConfigAction::Get { key },
            } => assert_eq!(key, "network"),
            _ => panic!("expected Config Get command"),
        }
    }

    #[test]
    fn test_cli_config_path_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "config", "path"]);
        assert!(matches!(
            cli.command,
            Commands::Config {
                action: ConfigAction::Path
            }
        ));
    }

    #[test]
    fn test_cli_global_config_path_override() {
        let cli = Cli::parse_from([
            "ark-cli",
            "--config-path",
            "/tmp/custom.toml",
            "config",
            "path",
        ]);
        assert_eq!(
            cli.config_path.as_deref().and_then(|p| p.to_str()),
            Some("/tmp/custom.toml")
        );
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

    #[test]
    fn test_cli_stealth_address_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "stealth", "address"]);
        assert!(matches!(
            cli.command,
            Commands::Stealth {
                action: StealthAction::Address
            }
        ));
    }

    #[test]
    fn test_cli_stealth_encode_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "stealth", "encode", "02aa", "02bb"]);
        match cli.command {
            Commands::Stealth {
                action:
                    StealthAction::Encode {
                        scan_pk_hex,
                        spend_pk_hex,
                        network: _,
                    },
            } => {
                assert_eq!(scan_pk_hex, "02aa");
                assert_eq!(spend_pk_hex, "02bb");
            }
            _ => panic!("expected Stealth Encode command"),
        }
    }

    #[test]
    fn test_cli_stealth_decode_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "stealth", "decode", "dark1xyz"]);
        match cli.command {
            Commands::Stealth {
                action: StealthAction::Decode { address },
            } => assert_eq!(address, "dark1xyz"),
            _ => panic!("expected Stealth Decode command"),
        }
    }

    #[test]
    fn test_cli_disclose_command_parses() {
        let cli = Cli::parse_from([
            "ark-cli",
            "disclose",
            "vtxo-1",
            "--selective-reveal",
            "--lower",
            "100",
            "--upper",
            "1000",
            "--source-of-funds",
            "root-1",
            "--out",
            "/tmp/bundle.json",
        ]);
        match cli.command {
            Commands::Disclose(args) => {
                assert_eq!(args.vtxo_id, "vtxo-1");
                assert!(args.selective_reveal);
                assert_eq!(args.lower, Some(100));
                assert_eq!(args.upper, Some(1000));
                assert_eq!(args.source_of_funds.as_deref(), Some("root-1"));
                assert_eq!(
                    args.out.as_deref().and_then(|p| p.to_str()),
                    Some("/tmp/bundle.json")
                );
            }
            _ => panic!("expected Disclose command"),
        }
    }

    #[test]
    fn test_cli_disclose_requires_paired_range_bounds() {
        let result = Cli::try_parse_from(["ark-cli", "disclose", "vtxo-1", "--lower", "100"]);
        assert!(result.is_err(), "--lower without --upper must fail");
    }

    #[test]
    fn test_cli_verify_command_parses() {
        let cli = Cli::parse_from(["ark-cli", "verify", "--in", "/tmp/bundle.json"]);
        match cli.command {
            Commands::Verify(args) => {
                assert_eq!(
                    args.input.as_deref().and_then(|p| p.to_str()),
                    Some("/tmp/bundle.json")
                );
            }
            _ => panic!("expected Verify command"),
        }
    }

    /// End-to-end round-trip: write the wallet config via the
    /// `config set` handler, then have the `receive` handler
    /// derive the meta-address from the same seed. This exercises
    /// the full disk → seed → meta-address path the README will
    /// document.
    #[test]
    fn config_set_then_receive_uses_persisted_seed() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");

        let mut config = wallet_config::WalletConfig::default();
        confidential::handle_config_set(
            &path,
            &mut config,
            "seed",
            &hex::encode([0x42u8; 32]),
            /*json*/ true,
        )
        .unwrap();
        confidential::handle_config_set(
            &path,
            &mut config,
            "default_confidential",
            "true",
            /*json*/ true,
        )
        .unwrap();

        // Reload from disk to prove persistence.
        let reloaded = wallet_config::load(&path).unwrap();
        assert!(reloaded.default_confidential);
        assert_eq!(reloaded.seed, hex::encode([0x42u8; 32]));

        // Capture stdout while we render `receive` and confirm the
        // address has the regtest HRP.
        let mut buf = Vec::new();
        writeln!(buf, "─── starting receive render ───").unwrap();
        // We can't easily redirect println! without a global hook; just
        // assert the function returns Ok and that the address is
        // derivable.
        confidential::handle_receive(&reloaded, /*json*/ true).expect("receive renders");
    }
}
