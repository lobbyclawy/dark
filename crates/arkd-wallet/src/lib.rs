//! # arkd-wallet
//!
//! Bitcoin wallet service for the Ark protocol server.
//!
//! This crate provides wallet functionality for the liquidity provider (LP),
//! including:
//!
//! - BDK-based descriptor wallet management
//! - UTXO tracking and coin selection
//! - Transaction signing (ECDSA and Schnorr)
//! - PSBT workflow support
//! - Key derivation and management
//!
//! ## Architecture
//!
//! The wallet service implements the [`WalletService`](arkd_core::ports::WalletService)
//! trait from arkd-core, allowing it to be easily swapped or mocked in tests.
//!
//! ## Example
//!
//! ```rust,ignore
//! use arkd_wallet::WalletManager;
//!
//! let wallet = WalletManager::new(config).await?;
//! let address = wallet.get_new_address().await?;
//! ```

use thiserror::Error;

pub mod config;
pub mod manager;
pub mod signer;

pub use config::WalletConfig;
pub use manager::WalletManager;
pub use signer::Signer;

/// Wallet-specific errors
#[derive(Error, Debug)]
pub enum WalletError {
    /// Failed to initialize wallet
    #[error("Wallet initialization failed: {0}")]
    InitializationError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Insufficient funds for transaction
    #[error("Insufficient funds: required {required} sats, available {available} sats")]
    InsufficientFunds { required: u64, available: u64 },

    /// Key derivation error
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    /// Signing error
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// BDK error
    #[error("BDK error: {0}")]
    BdkError(String),

    /// UTXO not found
    #[error("UTXO not found: {txid}:{vout}")]
    UtxoNotFound { txid: String, vout: u32 },

    /// Invalid descriptor
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),
}

/// Result type for wallet operations
pub type WalletResult<T> = Result<T, WalletError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_error_display() {
        let err = WalletError::InsufficientFunds {
            required: 100_000,
            available: 50_000,
        };
        assert!(err.to_string().contains("100000"));
    }
}
