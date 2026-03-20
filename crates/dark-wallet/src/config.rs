//! Wallet configuration
//!
//! Configuration for the BDK-based wallet service including network settings,
//! descriptor configuration, and sync parameters.

use bitcoin::Network;
use serde::{Deserialize, Serialize};

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Bitcoin network (mainnet, testnet, signet, regtest)
    pub network: Network,

    /// Esplora API endpoint for blockchain data
    /// Defaults based on network if not specified
    pub esplora_url: Option<String>,

    /// Path to wallet database file
    pub database_path: String,

    /// External descriptor (for receiving addresses)
    /// If not provided, a new descriptor will be generated
    pub external_descriptor: Option<String>,

    /// Internal descriptor (for change addresses)
    /// If not provided, derived from external descriptor
    pub internal_descriptor: Option<String>,

    /// BIP39 mnemonic for key generation
    /// Only used if descriptors are not provided
    pub mnemonic: Option<String>,

    /// Gap limit for address discovery
    #[serde(default = "default_gap_limit")]
    pub gap_limit: u32,

    /// Minimum confirmations for coin selection
    #[serde(default = "default_min_confirmations")]
    pub min_confirmations: u32,

    /// Stop gap for wallet sync
    #[serde(default = "default_stop_gap")]
    pub stop_gap: usize,

    /// Parallel request limit for esplora
    #[serde(default = "default_parallel_requests")]
    pub parallel_requests: usize,
}

fn default_gap_limit() -> u32 {
    20
}

fn default_min_confirmations() -> u32 {
    1
}

fn default_stop_gap() -> usize {
    50
}

fn default_parallel_requests() -> usize {
    5
}

impl WalletConfig {
    /// Create a new wallet configuration for regtest
    pub fn regtest(database_path: impl Into<String>) -> Self {
        Self {
            network: Network::Regtest,
            esplora_url: Some("http://localhost:3002".to_string()),
            database_path: database_path.into(),
            external_descriptor: None,
            internal_descriptor: None,
            mnemonic: None,
            gap_limit: default_gap_limit(),
            min_confirmations: 1,
            stop_gap: default_stop_gap(),
            parallel_requests: default_parallel_requests(),
        }
    }

    /// Create a new wallet configuration for testnet
    pub fn testnet(database_path: impl Into<String>) -> Self {
        Self {
            network: Network::Testnet,
            esplora_url: Some("https://blockstream.info/testnet/api".to_string()),
            database_path: database_path.into(),
            external_descriptor: None,
            internal_descriptor: None,
            mnemonic: None,
            gap_limit: default_gap_limit(),
            min_confirmations: 3,
            stop_gap: default_stop_gap(),
            parallel_requests: default_parallel_requests(),
        }
    }

    /// Create a new wallet configuration for mainnet
    pub fn mainnet(database_path: impl Into<String>) -> Self {
        Self {
            network: Network::Bitcoin,
            esplora_url: Some("https://blockstream.info/api".to_string()),
            database_path: database_path.into(),
            external_descriptor: None,
            internal_descriptor: None,
            mnemonic: None,
            gap_limit: default_gap_limit(),
            min_confirmations: 6,
            stop_gap: default_stop_gap(),
            parallel_requests: default_parallel_requests(),
        }
    }

    /// Get the esplora URL, using network defaults if not specified
    pub fn esplora_url(&self) -> String {
        self.esplora_url
            .clone()
            .unwrap_or_else(|| match self.network {
                Network::Bitcoin => "https://blockstream.info/api".to_string(),
                Network::Testnet => "https://blockstream.info/testnet/api".to_string(),
                Network::Signet => "https://mempool.space/signet/api".to_string(),
                Network::Regtest => "http://localhost:3002".to_string(),
                _ => "http://localhost:3002".to_string(),
            })
    }

    /// Set the external descriptor
    pub fn with_external_descriptor(mut self, descriptor: impl Into<String>) -> Self {
        self.external_descriptor = Some(descriptor.into());
        self
    }

    /// Set the internal descriptor
    pub fn with_internal_descriptor(mut self, descriptor: impl Into<String>) -> Self {
        self.internal_descriptor = Some(descriptor.into());
        self
    }

    /// Set the mnemonic for key derivation
    pub fn with_mnemonic(mut self, mnemonic: impl Into<String>) -> Self {
        self.mnemonic = Some(mnemonic.into());
        self
    }

    /// Set the esplora URL
    pub fn with_esplora_url(mut self, url: impl Into<String>) -> Self {
        self.esplora_url = Some(url.into());
        self
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self::regtest("./data/wallet.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WalletConfig::default();
        assert_eq!(config.network, Network::Regtest);
        assert_eq!(config.gap_limit, 20);
    }

    #[test]
    fn test_network_configs() {
        let mainnet = WalletConfig::mainnet("/tmp/wallet");
        assert_eq!(mainnet.network, Network::Bitcoin);
        assert_eq!(mainnet.min_confirmations, 6);

        let testnet = WalletConfig::testnet("/tmp/wallet");
        assert_eq!(testnet.network, Network::Testnet);
        assert_eq!(testnet.min_confirmations, 3);
    }

    #[test]
    fn test_builder_pattern() {
        let config = WalletConfig::regtest("/tmp/test")
            .with_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
            .with_esplora_url("http://custom:3002");

        assert!(config.mnemonic.is_some());
        assert_eq!(config.esplora_url(), "http://custom:3002");
    }
}
