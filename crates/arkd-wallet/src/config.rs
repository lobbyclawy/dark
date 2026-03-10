//! Wallet configuration

use serde::{Deserialize, Serialize};

/// Wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Network (mainnet, testnet, signet, regtest)
    pub network: String,

    /// Esplora API endpoint for blockchain data
    pub esplora_url: Option<String>,

    /// Path to wallet database file
    pub database_path: String,

    /// Wallet descriptor (external)
    pub descriptor: Option<String>,

    /// Change descriptor (internal)
    pub change_descriptor: Option<String>,

    /// Gap limit for address discovery
    #[serde(default = "default_gap_limit")]
    pub gap_limit: u32,

    /// Minimum confirmations for coin selection
    #[serde(default = "default_min_confirmations")]
    pub min_confirmations: u32,
}

fn default_gap_limit() -> u32 {
    20
}

fn default_min_confirmations() -> u32 {
    1
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            network: "regtest".to_string(),
            esplora_url: None,
            database_path: "./data/wallet.db".to_string(),
            descriptor: None,
            change_descriptor: None,
            gap_limit: default_gap_limit(),
            min_confirmations: default_min_confirmations(),
        }
    }
}
