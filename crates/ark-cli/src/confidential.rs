//! Confidential send / receive / scan subcommands.
//!
//! These three commands close the loop on confidential VTXOs from the
//! CLI:
//!
//! - `send` — submit a confidential VTXO transfer to a meta-address.
//!   Builds the transaction via `dark_client::create_confidential_tx`
//!   (#572). The builder is stubbed locally until #572 lands; see
//!   [`crate::confidential_tx_stub`].
//! - `receive` — print the wallet's stealth meta-address. Derives the
//!   keys from the configured seed via [`MetaAddress::from_seed`] so
//!   it matches the address the wallet will scan for.
//! - `scan` — run a one-shot stealth scan against the configured
//!   operator. Prints any newly discovered VTXOs as
//!   `(vtxo_id, amount, round_id)` triples.
//!
//! All three commands route through [`crate::wallet_config::WalletConfig`]
//! for the seed, network, and `default_confidential` toggle.

use anyhow::{anyhow, Context, Result};
use clap::Args;
use dark_client::stealth_scan::{
    scan_announcement, AnnouncementSource, ArkClientSource, ScannerCheckpoint, StealthMatch,
    DEFAULT_PAGE_LIMIT,
};
use dark_client::ArkClient;
use dark_confidential::stealth::{MetaAddress, StealthSecrets};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::confidential_tx_stub::{create_confidential_tx, ConfidentialSendRequest};
use crate::wallet_config::WalletConfig;

// ── send ────────────────────────────────────────────────────────────────────

/// CLI arguments for the `send` subcommand.
///
/// `--confidential` and `--no-confidential` are mutually exclusive; when
/// neither is given, the wallet's `default_confidential` setting wins.
#[derive(Args, Debug)]
pub struct SendArgs {
    /// Recipient meta-address (`darks1…` / `tdarks1…` / `rdarks1…`) for
    /// confidential sends. The legacy non-confidential path still
    /// accepts a hex pubkey here.
    #[arg(long)]
    pub to: String,

    /// Amount to send, in satoshis.
    #[arg(long)]
    pub amount: u64,

    /// Force a confidential send. Mutually exclusive with
    /// `--no-confidential`.
    #[arg(long, conflicts_with = "no_confidential")]
    pub confidential: bool,

    /// Force a non-confidential send. Mutually exclusive with
    /// `--confidential`.
    #[arg(long = "no-confidential")]
    pub no_confidential: bool,

    /// Optional sender memo. Cleartext for now — encryption lands
    /// with #536.
    #[arg(long)]
    pub memo: Option<String>,
}

impl SendArgs {
    /// Decide the effective confidential flag from the CLI flags and
    /// the wallet default.
    pub fn is_confidential(&self, default_confidential: bool) -> bool {
        if self.confidential {
            return true;
        }
        if self.no_confidential {
            return false;
        }
        default_confidential
    }
}

/// Render the result of a confidential send for human or JSON output.
pub fn handle_send(args: &SendArgs, config: &WalletConfig, json: bool) -> Result<()> {
    let confidential = args.is_confidential(config.default_confidential);
    if !confidential {
        return render_legacy_send(args, json);
    }

    let recipient = MetaAddress::from_bech32m(&args.to)
        .map_err(|e| anyhow!("--to is not a valid meta-address: {}", e))?;

    let outcome = create_confidential_tx(ConfidentialSendRequest {
        recipient: &recipient,
        amount_sats: args.amount,
        memo: args.memo.as_deref(),
    })?;

    if json {
        let out = serde_json::json!({
            "command": "send",
            "confidential": true,
            "to": args.to,
            "amount": outcome.amount_sats,
            "recipient_hrp": outcome.recipient_hrp,
            "memo": outcome.memo,
            "status": outcome.status,
            "note": "create_confidential_tx is stubbed pending #572; \
                     memo is cleartext pending #536"
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Confidential send (stubbed pending #572)");
        println!("───────────────────────────────────────");
        println!("  To:     {}", args.to);
        println!("  Amount: {} sats", outcome.amount_sats);
        if let Some(memo) = &outcome.memo {
            println!("  Memo:   {}", memo);
            println!("          (cleartext, pending #536)");
        }
        println!("  Status: {}", outcome.status);
    }
    Ok(())
}

fn render_legacy_send(args: &SendArgs, json: bool) -> Result<()> {
    if json {
        let out = serde_json::json!({
            "command": "send",
            "confidential": false,
            "to": args.to,
            "amount": args.amount,
            "memo": args.memo,
            "status": "not_implemented",
            "note": "Non-confidential send requires SubmitTx + FinalizeTx flow"
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Send command not yet implemented for non-confidential sends.");
        println!("Sending requires the SubmitTx + FinalizeTx flow.");
        println!("Would transfer {} sats to {}", args.amount, args.to);
    }
    Ok(())
}

// ── receive ─────────────────────────────────────────────────────────────────

/// Print the wallet's meta-address derived from the configured seed.
pub fn handle_receive(config: &WalletConfig, json: bool) -> Result<()> {
    let seed = config.decoded_seed()?;
    let network = config.stealth_network()?;
    let (meta, _secrets) = MetaAddress::from_seed(&seed, /* account_index */ 0, network)
        .map_err(|e| anyhow!("failed to derive meta-address from seed: {}", e))?;

    let address = meta.to_bech32m();

    if json {
        let out = serde_json::json!({
            "command": "receive",
            "address": address,
            "network": format!("{:?}", network),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Your stealth meta-address ({:?}):", network);
        println!("  {}", address);
        println!();
        println!("Share this address with senders to receive confidential VTXOs.");
        println!("Run `ark-cli scan` to detect inbound payments.");
    }
    Ok(())
}

// ── scan ────────────────────────────────────────────────────────────────────

/// Discovered VTXO returned by [`handle_scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredVtxo {
    pub vtxo_id: String,
    pub amount: u64,
    pub round_id: String,
}

/// Run a one-shot stealth scan against `client`. Prints discovered
/// VTXOs as `(vtxo_id, amount, round_id)` triples.
pub async fn handle_scan(client: ArkClient, config: &WalletConfig, json: bool) -> Result<()> {
    let secrets = derive_secrets(config)?;
    let source = ArkClientSource::new(Arc::new(Mutex::new(client)));

    let discovered = run_one_shot_scan(&source, &secrets).await?;
    render_scan_results(&discovered, json)
}

fn derive_secrets(config: &WalletConfig) -> Result<StealthSecrets> {
    let seed = config.decoded_seed()?;
    let network = config.stealth_network()?;
    let (_meta, secrets) = MetaAddress::from_seed(&seed, /* account_index */ 0, network)
        .map_err(|e| anyhow!("failed to derive scan/spend keys from seed: {}", e))?;
    Ok(secrets)
}

/// Single page of announcements pulled from `source` and matched
/// against the recipient's keys. Designed to be testable: callers pass
/// any [`AnnouncementSource`] and inspect the returned vector.
async fn run_one_shot_scan(
    source: &dyn AnnouncementSource,
    secrets: &StealthSecrets,
) -> Result<Vec<DiscoveredVtxo>> {
    let cursor = ScannerCheckpoint::default();
    let announcements = source
        .fetch(&cursor, DEFAULT_PAGE_LIMIT)
        .await
        .map_err(|e| anyhow!("operator fetch failed: {}", e))?;

    let scan_priv = secrets.scan_key.as_secret();
    let spend_pk = secrets.spend_key.pubkey();

    let mut discovered = Vec::new();
    for announcement in &announcements {
        let Some(matched) = scan_announcement(scan_priv, &spend_pk, announcement) else {
            continue;
        };
        discovered.push(materialize(source, &matched).await?);
    }
    Ok(discovered)
}

async fn materialize(
    source: &dyn AnnouncementSource,
    matched: &StealthMatch,
) -> Result<DiscoveredVtxo> {
    let amount = source
        .fetch_vtxo(matched)
        .await
        .map_err(|e| anyhow!("VTXO fetch failed: {}", e))?
        .map(|vtxo| vtxo.amount)
        .unwrap_or(0);
    Ok(DiscoveredVtxo {
        vtxo_id: matched.vtxo_id.clone(),
        amount,
        round_id: matched.round_id.clone(),
    })
}

fn render_scan_results(discovered: &[DiscoveredVtxo], json: bool) -> Result<()> {
    if json {
        let out = serde_json::json!({
            "command": "scan",
            "discovered": discovered
                .iter()
                .map(|v| serde_json::json!({
                    "vtxo_id": v.vtxo_id,
                    "amount": v.amount,
                    "round_id": v.round_id,
                }))
                .collect::<Vec<_>>(),
            "count": discovered.len(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if discovered.is_empty() {
        println!("No new VTXOs discovered.");
        return Ok(());
    }

    println!("Discovered VTXOs ({}):", discovered.len());
    println!("───────────────────────────────────────");
    for vtxo in discovered {
        println!(
            "  vtxo_id={} amount={} sats round_id={}",
            vtxo.vtxo_id, vtxo.amount, vtxo.round_id
        );
    }
    Ok(())
}

// ── config ──────────────────────────────────────────────────────────────────

/// Apply a `set` mutation: write the new value to disk and report it.
pub fn handle_config_set(
    path: &std::path::Path,
    config: &mut WalletConfig,
    key: &str,
    value: &str,
    json: bool,
) -> Result<()> {
    config.set_field(key, value)?;
    crate::wallet_config::save(path, config)
        .with_context(|| format!("failed to save config to {}", path.display()))?;

    if json {
        let out = serde_json::json!({
            "command": "config set",
            "key": key,
            "value": value,
            "path": path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("set {} = {}", key, value);
        println!("(saved to {})", path.display());
    }
    Ok(())
}

/// Print the value of a single config key.
pub fn handle_config_get(config: &WalletConfig, key: &str, json: bool) -> Result<()> {
    let value = config.get_field(key)?;
    if json {
        let out = serde_json::json!({ "key": key, "value": value });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("{}", value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dark_client::error::ClientResult;
    use dark_client::types::{RoundAnnouncement, Vtxo};
    use dark_confidential::stealth::StealthNetwork;

    /// Sample seed that produces a deterministic meta-address — used by
    /// the receive/scan tests so they match the same scanner keys.
    fn sample_seed_hex() -> String {
        hex::encode([7u8; 32])
    }

    fn config_with_seed() -> WalletConfig {
        WalletConfig {
            seed: sample_seed_hex(),
            network: "regtest".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn send_args_picks_explicit_confidential_flag() {
        let args = SendArgs {
            to: "darks1xyz".into(),
            amount: 100,
            confidential: true,
            no_confidential: false,
            memo: None,
        };
        assert!(args.is_confidential(false));
    }

    #[test]
    fn send_args_picks_explicit_no_confidential_flag() {
        let args = SendArgs {
            to: "02deadbeef".into(),
            amount: 100,
            confidential: false,
            no_confidential: true,
            memo: None,
        };
        assert!(!args.is_confidential(true));
    }

    #[test]
    fn send_args_falls_back_to_wallet_default() {
        let args = SendArgs {
            to: "darks1xyz".into(),
            amount: 100,
            confidential: false,
            no_confidential: false,
            memo: None,
        };
        assert!(args.is_confidential(true));
        assert!(!args.is_confidential(false));
    }

    /// Fake announcement source for the scan-loop unit test. Returns
    /// the scripted page on first fetch and an empty page thereafter.
    struct FakeSource {
        page: Vec<RoundAnnouncement>,
        vtxos: std::collections::HashMap<String, Vtxo>,
    }

    #[async_trait]
    impl AnnouncementSource for FakeSource {
        async fn fetch(
            &self,
            _cursor: &ScannerCheckpoint,
            _limit: u32,
        ) -> ClientResult<Vec<RoundAnnouncement>> {
            Ok(self.page.clone())
        }

        async fn fetch_vtxo(&self, matched: &StealthMatch) -> ClientResult<Option<Vtxo>> {
            Ok(self.vtxos.get(&matched.vtxo_id).cloned())
        }
    }

    fn vtxo_with_amount(id: &str, amount: u64, round_id: &str) -> Vtxo {
        Vtxo {
            id: id.to_string(),
            txid: id.to_string(),
            vout: 0,
            amount,
            script: String::new(),
            created_at: 0,
            expires_at: 0,
            is_spent: false,
            is_swept: false,
            is_unrolled: false,
            spent_by: String::new(),
            ark_txid: round_id.to_string(),
            assets: Vec::new(),
        }
    }

    fn announcement(round_id: &str, vtxo_id: &str, ephemeral: &str) -> RoundAnnouncement {
        RoundAnnouncement {
            cursor: format!("{round_id}\n{vtxo_id}"),
            round_id: round_id.into(),
            vtxo_id: vtxo_id.into(),
            ephemeral_pubkey: ephemeral.into(),
        }
    }

    #[tokio::test]
    async fn one_shot_scan_returns_matching_vtxos_with_amounts() {
        let cfg = config_with_seed();
        let seed = cfg.decoded_seed().unwrap();
        let (_meta, secrets) = MetaAddress::from_seed(&seed, 0, StealthNetwork::Regtest).unwrap();

        // The stub matcher in dark_client fires when ephemeral_pubkey
        // equals the hex-encoded spend pk. Drive a hit and a miss.
        let spend_pk_hex = hex::encode(secrets.spend_key.pubkey().serialize());
        let mut vtxos = std::collections::HashMap::new();
        vtxos.insert(
            "tx-hit:0".to_string(),
            vtxo_with_amount("tx-hit:0", 12_345, "round-001"),
        );

        let source = FakeSource {
            page: vec![
                announcement("round-001", "tx-miss:0", "decoy"),
                announcement("round-001", "tx-hit:0", &spend_pk_hex),
            ],
            vtxos,
        };

        let discovered = run_one_shot_scan(&source, &secrets).await.unwrap();
        assert_eq!(
            discovered,
            vec![DiscoveredVtxo {
                vtxo_id: "tx-hit:0".into(),
                amount: 12_345,
                round_id: "round-001".into(),
            }]
        );
    }

    #[tokio::test]
    async fn one_shot_scan_returns_zero_amount_when_vtxo_not_yet_materialized() {
        let cfg = config_with_seed();
        let seed = cfg.decoded_seed().unwrap();
        let (_meta, secrets) = MetaAddress::from_seed(&seed, 0, StealthNetwork::Regtest).unwrap();

        let spend_pk_hex = hex::encode(secrets.spend_key.pubkey().serialize());

        // Empty `vtxos` map — fetch_vtxo returns None for every match.
        let source = FakeSource {
            page: vec![announcement("round-007", "tx-pending:0", &spend_pk_hex)],
            vtxos: std::collections::HashMap::new(),
        };

        let discovered = run_one_shot_scan(&source, &secrets).await.unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].vtxo_id, "tx-pending:0");
        assert_eq!(discovered[0].amount, 0);
    }

    #[test]
    fn handle_send_rejects_invalid_meta_address() {
        let cfg = config_with_seed();
        let args = SendArgs {
            to: "not-a-meta-address".into(),
            amount: 100,
            confidential: true,
            no_confidential: false,
            memo: None,
        };
        let err = handle_send(&args, &cfg, /*json*/ true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid meta-address"));
    }
}
