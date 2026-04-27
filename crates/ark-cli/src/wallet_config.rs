//! On-disk wallet configuration for `ark-cli`.
//!
//! The wallet config holds a small set of UX-level preferences that
//! survive across CLI invocations:
//!
//! - `default_confidential` — whether `send` defaults to a confidential
//!   send when neither `--confidential` nor `--no-confidential` is
//!   passed.
//! - `seed` — the wallet's BIP-32 master seed, hex-encoded. Used by
//!   `receive` and `scan` to derive the stealth meta-address. Stored as
//!   plaintext on disk (TODO(#553): swap in a keychain-backed store).
//! - `network` — stealth network (mainnet/testnet/regtest), driving the
//!   bech32m HRP of the meta-address.
//!
//! The config is a small TOML file. The default path resolution is
//! `$XDG_CONFIG_HOME/ark-cli/config.toml`, falling back to
//! `$HOME/.config/ark-cli/config.toml`. Tests and power users can
//! override via `--config-path`.
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use dark_confidential::stealth::StealthNetwork;
use serde::{Deserialize, Serialize};

/// File name of the wallet config inside its directory.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Subdirectory under `$XDG_CONFIG_HOME` (or `$HOME/.config`) that the
/// wallet config lives in.
const CONFIG_SUBDIR: &str = "ark-cli";

/// Wallet UX preferences and key material persisted between CLI runs.
///
/// `Default` and `serde`'s `default` attributes share a single source
/// of truth: the inherent `default()` impl below. That impl is the
/// authoritative initialiser, and the `#[serde(default = "...")]`
/// hooks delegate to it so a TOML file with a missing field hydrates
/// the same value as `WalletConfig::default()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletConfig {
    /// When true, `send` defaults to a confidential send unless
    /// `--no-confidential` is explicitly passed.
    #[serde(default)]
    pub default_confidential: bool,

    /// Hex-encoded BIP-32 master seed. Used by `receive` and `scan` to
    /// derive the stealth scan/spend keys. Empty until the user runs
    /// `ark-cli config set seed <hex>` (or, eventually, `init`).
    #[serde(default)]
    pub seed: String,

    /// Stealth network for derived addresses. Stored as a lowercase
    /// string (`mainnet` / `testnet` / `regtest`) for human-friendly
    /// hand-edits.
    #[serde(default = "default_network_string")]
    pub network: String,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            default_confidential: false,
            seed: String::new(),
            network: default_network_string(),
        }
    }
}

fn default_network_string() -> String {
    "regtest".to_string()
}

impl WalletConfig {
    /// Resolve the network setting to a [`StealthNetwork`]. Errors if the
    /// stored string is not one of the recognised values.
    pub fn stealth_network(&self) -> Result<StealthNetwork> {
        match self.network.as_str() {
            "mainnet" => Ok(StealthNetwork::Mainnet),
            "testnet" => Ok(StealthNetwork::Testnet),
            "regtest" => Ok(StealthNetwork::Regtest),
            other => Err(anyhow!(
                "unknown network '{}': expected mainnet | testnet | regtest",
                other
            )),
        }
    }

    /// Decode the hex seed into raw bytes. Errors if the seed is empty
    /// or malformed.
    pub fn decoded_seed(&self) -> Result<Vec<u8>> {
        if self.seed.is_empty() {
            return Err(anyhow!(
                "no wallet seed configured; run `ark-cli config set seed <hex>` first"
            ));
        }
        hex::decode(&self.seed).context("wallet seed is not valid hex")
    }

    /// Apply a `key=value` mutation, returning a clear error for
    /// unknown keys or malformed values.
    pub fn set_field(&mut self, key: &str, value: &str) -> Result<()> {
        match key {
            "default_confidential" => {
                self.default_confidential = parse_bool(value)?;
            }
            "seed" => {
                if !value.is_empty() {
                    hex::decode(value).context("seed must be valid hex")?;
                }
                self.seed = value.to_string();
            }
            "network" => {
                if !matches!(value, "mainnet" | "testnet" | "regtest") {
                    return Err(anyhow!("network must be one of: mainnet, testnet, regtest"));
                }
                value.clone_into(&mut self.network);
            }
            other => {
                return Err(anyhow!(
                    "unknown config key '{}': expected one of \
                     default_confidential, seed, network",
                    other
                ));
            }
        }
        Ok(())
    }

    /// Read the named field as a string for `config get`.
    pub fn get_field(&self, key: &str) -> Result<String> {
        match key {
            "default_confidential" => Ok(self.default_confidential.to_string()),
            "seed" => Ok(self.seed.clone()),
            "network" => Ok(self.network.clone()),
            other => Err(anyhow!(
                "unknown config key '{}': expected one of \
                 default_confidential, seed, network",
                other
            )),
        }
    }
}

/// Resolve the wallet config path: explicit override wins, otherwise
/// fall back to `$XDG_CONFIG_HOME/ark-cli/config.toml`, otherwise
/// `$HOME/.config/ark-cli/config.toml`.
///
/// Returns an error if neither `XDG_CONFIG_HOME` nor `HOME` is set —
/// callers should pass `--config-path` in that case.
pub fn resolve_config_path(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path.to_path_buf());
    }

    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Ok(PathBuf::from(xdg)
                .join(CONFIG_SUBDIR)
                .join(CONFIG_FILE_NAME));
        }
    }

    let home = std::env::var("HOME").map_err(|_| {
        anyhow!(
            "neither XDG_CONFIG_HOME nor HOME is set; pass --config-path to \
             specify the wallet config explicitly"
        )
    })?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join(CONFIG_SUBDIR)
        .join(CONFIG_FILE_NAME))
}

/// Load the wallet config from `path`, or return a fresh default if the
/// file does not yet exist.
pub fn load(path: &Path) -> Result<WalletConfig> {
    if !path.exists() {
        return Ok(WalletConfig::default());
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config from {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse config at {}", path.display()))
}

/// Write the wallet config back to `path`, creating its parent
/// directory if needed.
pub fn save(path: &Path, config: &WalletConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config dir {}", parent.display()))?;
    }
    let serialized = toml::to_string_pretty(config).context("failed to encode config as TOML")?;
    fs::write(path, serialized)
        .with_context(|| format!("failed to write config to {}", path.display()))
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(anyhow!("expected a boolean (true/false), got '{}'", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_config_has_safe_defaults() {
        let cfg = WalletConfig::default();
        assert!(!cfg.default_confidential);
        assert!(cfg.seed.is_empty());
        assert_eq!(cfg.network, "regtest");
    }

    #[test]
    fn set_default_confidential_accepts_truthy_strings() {
        let mut cfg = WalletConfig::default();
        cfg.set_field("default_confidential", "true").unwrap();
        assert!(cfg.default_confidential);
        cfg.set_field("default_confidential", "false").unwrap();
        assert!(!cfg.default_confidential);
        cfg.set_field("default_confidential", "yes").unwrap();
        assert!(cfg.default_confidential);
    }

    #[test]
    fn set_default_confidential_rejects_garbage() {
        let mut cfg = WalletConfig::default();
        let err = cfg
            .set_field("default_confidential", "maybe")
            .unwrap_err()
            .to_string();
        assert!(err.contains("boolean"));
    }

    #[test]
    fn set_seed_validates_hex() {
        let mut cfg = WalletConfig::default();
        cfg.set_field("seed", "deadbeef").unwrap();
        assert_eq!(cfg.seed, "deadbeef");
        let err = cfg.set_field("seed", "not-hex").unwrap_err().to_string();
        assert!(err.contains("hex"));
    }

    #[test]
    fn set_network_rejects_unknown_value() {
        let mut cfg = WalletConfig::default();
        cfg.set_field("network", "mainnet").unwrap();
        assert_eq!(cfg.network, "mainnet");
        let err = cfg.set_field("network", "darknet").unwrap_err().to_string();
        assert!(err.contains("mainnet"));
    }

    #[test]
    fn set_field_rejects_unknown_key() {
        let mut cfg = WalletConfig::default();
        let err = cfg.set_field("nope", "value").unwrap_err().to_string();
        assert!(err.contains("unknown config key"));
    }

    #[test]
    fn get_field_returns_current_values() {
        let cfg = WalletConfig {
            default_confidential: true,
            seed: "ab".to_string(),
            network: "testnet".to_string(),
        };
        assert_eq!(cfg.get_field("default_confidential").unwrap(), "true");
        assert_eq!(cfg.get_field("seed").unwrap(), "ab");
        assert_eq!(cfg.get_field("network").unwrap(), "testnet");
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("config.toml");

        let cfg = WalletConfig {
            default_confidential: true,
            seed: "00".repeat(32),
            network: "testnet".to_string(),
        };

        save(&path, &cfg).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded, cfg);
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.toml");
        let cfg = load(&path).unwrap();
        assert_eq!(cfg, WalletConfig::default());
    }

    #[test]
    fn stealth_network_resolves_known_strings() {
        for (label, expected) in [
            ("mainnet", StealthNetwork::Mainnet),
            ("testnet", StealthNetwork::Testnet),
            ("regtest", StealthNetwork::Regtest),
        ] {
            let cfg = WalletConfig {
                network: label.to_string(),
                ..Default::default()
            };
            assert_eq!(cfg.stealth_network().unwrap(), expected);
        }
    }

    #[test]
    fn decoded_seed_errors_when_empty() {
        let cfg = WalletConfig::default();
        let err = cfg.decoded_seed().unwrap_err().to_string();
        assert!(err.contains("no wallet seed configured"));
    }
}
