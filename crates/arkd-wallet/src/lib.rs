//! # arkd-wallet
//!
//! Bitcoin wallet service for the Ark protocol server.
//!
//! This crate provides comprehensive wallet functionality for the Ark Service
//! Provider (ASP), including:
//!
//! - **BDK Integration**: Full Bitcoin Development Kit (1.0) integration for
//!   descriptor-based wallet management
//! - **UTXO Management**: Tracking, coin selection, and reservation of UTXOs
//! - **Transaction Signing**: ECDSA and Schnorr (Taproot) signature support
//! - **PSBT Workflow**: Full PSBT creation, signing, and finalization
//! - **Key Management**: BIP86 (Taproot) key derivation and ASP key generation
//! - **Blockchain Sync**: Esplora-based wallet synchronization
//!
//! ## Architecture
//!
//! The wallet service implements the [`WalletService`](arkd_core::ports::WalletService)
//! trait from arkd-core, enabling clean separation between the core domain logic
//! and wallet infrastructure.
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                       arkd-core                               │
//! │  ┌─────────────────────────────────────────────────────────┐ │
//! │  │              WalletService (port/trait)                 │ │
//! │  └─────────────────────────────────────────────────────────┘ │
//! └────────────────────────────┬─────────────────────────────────┘
//!                              │ implements
//! ┌────────────────────────────▼─────────────────────────────────┐
//! │                       arkd-wallet                            │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
//! │  │  WalletManager  │  │     Signer      │  │ CoinSelector │ │
//! │  │  (BDK Wallet)   │  │ (ECDSA/Schnorr) │  │  (Strategies)│ │
//! │  └────────┬────────┘  └────────┬────────┘  └──────────────┘ │
//! └───────────┼────────────────────┼────────────────────────────┘
//!             │                    │
//!   ┌─────────▼────────┐   ┌───────▼────────┐
//!   │   bdk_wallet     │   │   secp256k1    │
//!   │   bdk_esplora    │   │                │
//!   │   bdk_file_store │   │                │
//!   └──────────────────┘   └────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use arkd_wallet::{WalletConfig, WalletManager, WalletServiceImpl};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Configure wallet for regtest
//!     let config = WalletConfig::regtest("./data/wallet.db")
//!         .with_mnemonic("abandon abandon ... about");
//!
//!     // Create wallet manager
//!     let manager = Arc::new(WalletManager::new(config).await?);
//!
//!     // Sync with blockchain
//!     manager.sync().await?;
//!
//!     // Get a new address
//!     let address = manager.get_new_address().await?;
//!     println!("Send BTC to: {}", address);
//!
//!     // Create service implementing WalletService trait
//!     let service = WalletServiceImpl::new(manager);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! ### Coin Selection
//!
//! Multiple coin selection strategies are available:
//!
//! - **LargestFirst**: Simple, good for consolidation
//! - **BranchAndBound**: Optimal, tries to avoid change outputs
//! - **RandomDraw**: Privacy-preserving random selection
//! - **ArkOptimized**: Optimized for Ark round funding
//!
//! ```rust,ignore
//! use arkd_wallet::coin_selection::{CoinSelector, CoinSelectionStrategy};
//! use bitcoin::Amount;
//!
//! let selector = CoinSelector::new(2.0) // 2 sat/vB fee rate
//!     .with_strategy(CoinSelectionStrategy::ArkOptimized);
//!
//! let result = selector.select(&utxos, Amount::from_sat(100_000), 1)?;
//! ```
//!
//! ### Transaction Signing
//!
//! The `Signer` provides both ECDSA and Schnorr signing:
//!
//! ```rust,ignore
//! use arkd_wallet::Signer;
//!
//! let signer = Signer::new();
//!
//! // Schnorr signing for Taproot
//! let sig = signer.sign_schnorr(&message_hash, &keypair)?;
//!
//! // Taproot key-path signing
//! let sig = signer.sign_taproot_key_spend(
//!     &tx, input_index, &prevouts, &keypair, sighash_type
//! )?;
//! ```

use thiserror::Error;

pub mod coin_selection;
pub mod config;
pub mod manager;
pub mod service;
pub mod signer;

pub use coin_selection::{CoinSelectionResult, CoinSelectionStrategy, CoinSelector};
pub use config::WalletConfig;
pub use manager::{SyncResult, WalletBalance, WalletManager, WalletUtxo};
pub use service::{WalletServiceBuilder, WalletServiceImpl};
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
    InsufficientFunds {
        /// Amount required
        required: u64,
        /// Amount available
        available: u64,
    },

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
    UtxoNotFound {
        /// Transaction ID
        txid: String,
        /// Output index
        vout: u32,
    },

    /// Invalid descriptor
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),

    /// Broadcast error
    #[error("Transaction broadcast failed: {0}")]
    BroadcastError(String),

    /// Sync error
    #[error("Wallet sync failed: {0}")]
    SyncError(String),
}

/// Result type for wallet operations
pub type WalletResult<T> = Result<T, WalletError>;

/// Re-export bitcoin types commonly used with wallet
pub mod bitcoin_types {
    pub use bitcoin::psbt::Psbt;
    pub use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
    pub use bitcoin::{
        Address, Amount, Network, OutPoint, Transaction, TxOut, Txid, XOnlyPublicKey,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_error_display() {
        let err = WalletError::InsufficientFunds {
            required: 100_000,
            available: 50_000,
        };
        let msg = err.to_string();
        assert!(msg.contains("100000"));
        assert!(msg.contains("50000"));
    }

    #[test]
    fn test_wallet_error_variants() {
        // Ensure all error variants are constructible
        let _init = WalletError::InitializationError("test".to_string());
        let _config = WalletError::ConfigError("test".to_string());
        let _key = WalletError::KeyDerivationError("test".to_string());
        let _sign = WalletError::SigningError("test".to_string());
        let _bdk = WalletError::BdkError("test".to_string());
        let _utxo = WalletError::UtxoNotFound {
            txid: "abc".to_string(),
            vout: 0,
        };
        let _desc = WalletError::InvalidDescriptor("test".to_string());
        let _broadcast = WalletError::BroadcastError("test".to_string());
        let _sync = WalletError::SyncError("test".to_string());
    }
}
