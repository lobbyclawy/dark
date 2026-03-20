use serde::{Deserialize, Serialize};
use std::path::Path;

/// Deployment mode: Full (Redis + PostgreSQL) or Light (SQLite + in-memory).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    #[default]
    Full,
    Light,
}

/// Top-level config file structure (config.toml)
#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[allow(dead_code)] // Will be used when Bitcoin RPC is wired
    #[serde(default)]
    pub bitcoin: BitcoinSection,
    #[serde(default)]
    pub ark: ArkSection,
    #[serde(default)]
    pub deployment: DeploymentSection,
    /// Wallet configuration for the BDK-backed operator wallet.
    #[serde(default)]
    pub wallet: WalletSection,
    #[serde(default)]
    pub fees: FeesSection,
    /// Nostr integration for VTXO expiry notifications (Issue #247)
    #[serde(default)]
    pub nostr: NostrSection,
}

/// Deployment configuration section.
#[derive(Debug, Deserialize, Default)]
pub struct DeploymentSection {
    /// Deployment mode: "full" (default) or "light".
    #[serde(default)]
    pub mode: DeploymentMode,
}

impl DeploymentSection {
    /// Returns `true` when the deployment is configured for light mode.
    pub fn is_light(&self) -> bool {
        matches!(self.mode, DeploymentMode::Light)
    }

    /// Human-readable label for the store backends implied by the current mode.
    pub fn store_info(&self) -> &'static str {
        if self.is_light() {
            "sqlite+in-memory"
        } else {
            "postgresql+redis"
        }
    }
}

/// Nostr integration configuration section.
///
/// When `relay_url` and `private_key_hex` are both set, the server will
/// create a `NostrNotifier` that sends NIP-04 encrypted DMs about VTXO
/// expiry events to affected users.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct NostrSection {
    /// WebSocket URL of the Nostr relay (e.g. `wss://relay.damus.io`)
    pub relay_url: Option<String>,
    /// 32-byte hex-encoded private key for signing Nostr events
    pub private_key_hex: Option<String>,
    /// URI prefix for note references in notifications
    #[allow(dead_code)]
    pub note_uri_prefix: Option<String>,
}

impl NostrSection {
    /// Returns `true` when both relay_url and private_key_hex are configured.
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.relay_url.is_some() && self.private_key_hex.is_some()
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ServerSection {
    pub grpc_addr: Option<String>,
    pub rest_addr: Option<String>,
    pub require_auth: Option<bool>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub asp_key_hex: Option<String>,
    pub esplora_url: Option<String>,
    pub admin_token: Option<String>,
    /// Disable macaroon-based authentication.
    pub no_macaroons: Option<bool>,
    /// Disable TLS (plaintext mode).
    pub no_tls: Option<bool>,
    /// Unlocker type: env or file.
    pub unlocker_type: Option<String>,
    /// Path to the password file when unlocker_type = file.
    pub unlocker_file_path: Option<String>,
    /// OpenTelemetry OTLP collector endpoint (e.g. "http://localhost:4317").
    /// See: <https://github.com/lobbyclawy/arkd-rs/issues/245>
    pub otlp_endpoint: Option<String>,
    /// Pyroscope continuous profiling URL (stub, not yet wired).
    /// TODO(#245): wire Pyroscope integration.
    #[allow(dead_code)]
    pub pyroscope_url: Option<String>,
    /// Prometheus Alertmanager URL for operational alerts (e.g. "http://alertmanager:9093").
    /// When set, alerts are pushed to the Alertmanager API instead of being silently discarded.
    pub alertmanager_url: Option<String>,
}

#[allow(dead_code)] // Fields will be used when Bitcoin RPC integration is wired
#[derive(Debug, Deserialize, Default)]
pub struct BitcoinSection {
    pub network: Option<String>,
    pub rpc_host: Option<String>,
    pub rpc_port: Option<u16>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ArkSection {
    pub round_duration_secs: Option<u64>,
    pub round_interval_blocks: Option<u32>,
    pub allow_csv_block_type: Option<bool>,
    /// Maximum number of distinct assets allowed per VTXO.
    #[allow(dead_code)]
    pub max_assets_per_vtxo: Option<u32>,
}

/// Operator wallet configuration for BDK-backed wallet service.
///
/// When `descriptor` and `esplora_url` are both set, the server will
/// instantiate a [`BdkWalletService`](arkd_wallet::BdkWalletService) instead
/// of the stub wallet. This enables real on-chain wallet operations
/// (seed generation, address derivation, balance queries, withdrawals).
///
/// # Example (config.toml)
///
/// ```toml
/// [wallet]
/// descriptor = "tr(tprv8Zgx.../86\'/1\'/0\'/0/*)"
/// change_descriptor = "tr(tprv8Zgx.../86\'/1\'/0\'/1/*)"
/// network = "regtest"
/// esplora_url = "http://localhost:3002"
/// ```
#[derive(Debug, Deserialize, Default)]
pub struct WalletSection {
    /// BIP86 Taproot external (receiving) output descriptor.
    pub descriptor: Option<String>,
    /// BIP86 Taproot internal (change) output descriptor.
    pub change_descriptor: Option<String>,
    /// Bitcoin network: "bitcoin", "testnet", "signet", or "regtest".
    /// Defaults to "regtest" if unset.
    pub network: Option<String>,
    /// Esplora HTTP API URL for blockchain sync and broadcasting.
    pub esplora_url: Option<String>,
}

impl WalletSection {
    /// Returns `true` when both descriptor and esplora_url are configured,
    /// indicating the real BDK wallet should be used.
    pub fn is_configured(&self) -> bool {
        self.descriptor.is_some() && self.esplora_url.is_some()
    }

    /// Parse the network string into a `bitcoin::Network`.
    /// Defaults to `Regtest` if unset or unrecognised.
    pub fn parse_network(&self) -> bitcoin::Network {
        match self.network.as_deref() {
            Some("bitcoin") | Some("mainnet") => bitcoin::Network::Bitcoin,
            Some("testnet") | Some("testnet3") => bitcoin::Network::Testnet,
            Some("signet") => bitcoin::Network::Signet,
            _ => bitcoin::Network::Regtest,
        }
    }
}

impl FileConfig {
    /// Shortcut: is the deployment mode set to light?
    pub fn is_light_mode(&self) -> bool {
        self.deployment.is_light()
    }

    /// Shortcut: human-readable store backend label.
    pub fn store_info(&self) -> &'static str {
        self.deployment.store_info()
    }
}

/// Fee program configuration section (`[fees]` in config.toml).
///
/// Maps to `FeeProgram` domain model. All fields default to 0 if not specified.
#[derive(Debug, Deserialize, Default)]
pub struct FeesSection {
    /// Satoshis per offchain input (e.g. VTXO being refreshed)
    pub offchain_input_fee: Option<u64>,
    /// Satoshis per onchain input (e.g. boarding UTXO)
    pub onchain_input_fee: Option<u64>,
    /// Satoshis per offchain output (VTXO being created)
    pub offchain_output_fee: Option<u64>,
    /// Satoshis per onchain output (on-chain exit)
    pub onchain_output_fee: Option<u64>,
    /// Base fee per intent regardless of inputs/outputs
    pub base_fee: Option<u64>,
}

/// Load config from file path. Returns default config if file doesn't exist.
pub fn load_config(path: &Path) -> anyhow::Result<FileConfig> {
    if !path.exists() {
        tracing::warn!(path = %path.display(), "Config file not found, using defaults");
        return Ok(FileConfig::default());
    }
    let content = std::fs::read_to_string(path)?;
    let config: FileConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Config parse error in {}: {e}", path.display()))?;
    tracing::info!(path = %path.display(), "Config loaded");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_config_missing_file_returns_default() {
        let result = load_config(Path::new("/tmp/nonexistent_arkd_config.toml"));
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_load_config_parses_grpc_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[server]\ngrpc_addr = \"0.0.0.0:9999\"").unwrap();

        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.server.grpc_addr.as_deref(), Some("0.0.0.0:9999"));
    }

    #[test]
    fn test_load_config_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "{{{{not valid toml").unwrap();

        let result = load_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();

        let cfg = load_config(&path).unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.bitcoin.network.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_deployment_mode_default_is_full() {
        let mode = DeploymentMode::default();
        assert_eq!(mode, DeploymentMode::Full);
    }

    #[test]
    fn test_deployment_mode_serde_light() {
        let json = serde_json::to_string(&DeploymentMode::Light).unwrap();
        assert_eq!(json, "\"light\"");
        let parsed: DeploymentMode = serde_json::from_str("\"light\"").unwrap();
        assert_eq!(parsed, DeploymentMode::Light);
    }

    #[test]
    fn test_deployment_mode_serde_full() {
        let json = serde_json::to_string(&DeploymentMode::Full).unwrap();
        assert_eq!(json, "\"full\"");
        let parsed: DeploymentMode = serde_json::from_str("\"full\"").unwrap();
        assert_eq!(parsed, DeploymentMode::Full);
    }

    #[test]
    fn test_cli_default_config_path() {
        use crate::cli::Cli;
        use clap::Parser;

        let cli = Cli::try_parse_from(["arkd"]).unwrap();
        assert_eq!(cli.config, "config.toml");
    }

    // ── Issue #119: deployment-mode wiring tests ──

    #[test]
    fn test_light_mode_is_light_returns_true() {
        let section = DeploymentSection {
            mode: DeploymentMode::Light,
        };
        assert!(section.is_light());
    }

    #[test]
    fn test_full_mode_is_light_returns_false() {
        let section = DeploymentSection {
            mode: DeploymentMode::Full,
        };
        assert!(!section.is_light());
    }

    #[test]
    fn test_store_info_light_vs_full() {
        let light = DeploymentSection {
            mode: DeploymentMode::Light,
        };
        assert_eq!(light.store_info(), "sqlite+in-memory");

        let full = DeploymentSection {
            mode: DeploymentMode::Full,
        };
        assert_eq!(full.store_info(), "postgresql+redis");
    }

    // ── Issue #238: wallet section tests ──

    #[test]
    fn test_wallet_section_default_not_configured() {
        let section = WalletSection::default();
        assert!(!section.is_configured());
    }

    #[test]
    fn test_wallet_section_configured_when_both_set() {
        let section = WalletSection {
            descriptor: Some("tr(...)".into()),
            change_descriptor: Some("tr(...)".into()),
            network: None,
            esplora_url: Some("http://localhost:3002".into()),
        };
        assert!(section.is_configured());
    }

    #[test]
    fn test_wallet_section_not_configured_missing_esplora() {
        let section = WalletSection {
            descriptor: Some("tr(...)".into()),
            change_descriptor: None,
            network: None,
            esplora_url: None,
        };
        assert!(!section.is_configured());
    }

    #[test]
    fn test_wallet_parse_network_defaults_regtest() {
        let section = WalletSection::default();
        assert_eq!(section.parse_network(), bitcoin::Network::Regtest);
    }

    #[test]
    fn test_wallet_parse_network_mainnet() {
        let section = WalletSection {
            network: Some("bitcoin".into()),
            ..Default::default()
        };
        assert_eq!(section.parse_network(), bitcoin::Network::Bitcoin);
    }

    #[test]
    fn test_wallet_parse_network_signet() {
        let section = WalletSection {
            network: Some("signet".into()),
            ..Default::default()
        };
        assert_eq!(section.parse_network(), bitcoin::Network::Signet);
    }

    #[test]
    fn test_load_config_with_wallet_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "[wallet]\ndescriptor = \"tr(tprv...)\"\nesplora_url = \"http://localhost:3002\""
        )
        .unwrap();

        let cfg = load_config(&path).unwrap();
        assert!(cfg.wallet.is_configured());
        assert_eq!(
            cfg.wallet.esplora_url.as_deref(),
            Some("http://localhost:3002")
        );
    }
}
