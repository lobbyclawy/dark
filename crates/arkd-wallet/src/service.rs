//! WalletService trait implementation
//!
//! Implements the `WalletService` port from arkd-core, providing the interface
//! between the core domain logic and the BDK wallet implementation.

use async_trait::async_trait;
use bitcoin::{Address, Amount, Transaction, Txid, XOnlyPublicKey};
use std::sync::Arc;

use arkd_core::error::ArkResult;
use arkd_core::ports::{WalletService, WalletUtxo as PortWalletUtxo};

use crate::manager::{WalletManager, WalletUtxo};
use crate::WalletError;

/// Wallet service adapter implementing the WalletService port
///
/// This adapter wraps the WalletManager and implements the port interface
/// defined in arkd-core, enabling the core application to use wallet
/// functionality without depending on BDK directly.
pub struct WalletServiceImpl {
    manager: Arc<WalletManager>,
}

impl WalletServiceImpl {
    /// Create a new wallet service from a wallet manager
    pub fn new(manager: Arc<WalletManager>) -> Self {
        Self { manager }
    }

    /// Get the underlying wallet manager
    pub fn manager(&self) -> &Arc<WalletManager> {
        &self.manager
    }

    /// Sync the wallet with the blockchain
    pub async fn sync(&self) -> ArkResult<()> {
        self.manager
            .sync()
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))?;
        Ok(())
    }
}

impl From<WalletUtxo> for PortWalletUtxo {
    fn from(utxo: WalletUtxo) -> Self {
        PortWalletUtxo {
            outpoint: utxo.outpoint,
            amount: utxo.amount,
            confirmations: utxo.confirmations,
            reserved: utxo.reserved,
        }
    }
}

#[async_trait]
impl WalletService for WalletServiceImpl {
    /// Get the current wallet balance (confirmed + trusted pending)
    async fn get_balance(&self) -> ArkResult<Amount> {
        let balance = self
            .manager
            .get_balance()
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))?;

        Ok(balance.total())
    }

    /// Get available (confirmed) balance with minimum confirmations
    async fn get_available_balance(&self, min_confirmations: u32) -> ArkResult<Amount> {
        self.manager
            .get_available_balance(min_confirmations)
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))
    }

    /// Generate a new receiving address
    async fn get_new_address(&self) -> ArkResult<Address> {
        self.manager
            .get_new_address()
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))
    }

    /// Get list of available UTXOs with minimum confirmations
    async fn get_utxos(&self, min_confirmations: u32) -> ArkResult<Vec<PortWalletUtxo>> {
        let utxos = self
            .manager
            .get_utxos(min_confirmations)
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))?;

        Ok(utxos.into_iter().map(Into::into).collect())
    }

    /// Sign a PSBT with the wallet's keys
    async fn sign_psbt(&self, psbt: &mut bitcoin::psbt::Psbt) -> ArkResult<()> {
        self.manager
            .sign_psbt(psbt)
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))?;

        Ok(())
    }

    /// Sign a message with the wallet's ASP key (Schnorr)
    async fn sign_message(&self, message: &[u8]) -> ArkResult<Vec<u8>> {
        // Message must be exactly 32 bytes for Schnorr signing
        if message.len() != 32 {
            return Err(arkd_core::error::ArkError::WalletError(
                "Message must be exactly 32 bytes".to_string(),
            ));
        }

        let mut msg = [0u8; 32];
        msg.copy_from_slice(message);

        let sig = self
            .manager
            .sign_message(&msg)
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))?;

        Ok(sig.as_ref().to_vec())
    }

    /// Broadcast a transaction to the Bitcoin network
    async fn broadcast_transaction(&self, tx: &Transaction) -> ArkResult<Txid> {
        self.manager
            .broadcast_transaction(tx)
            .await
            .map_err(|e| arkd_core::error::ArkError::WalletError(e.to_string()))
    }

    /// Get the ASP's x-only public key (for VTXO scripts)
    async fn get_asp_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(self.manager.asp_pubkey())
    }
}

/// Builder for creating WalletServiceImpl
pub struct WalletServiceBuilder {
    manager: Option<Arc<WalletManager>>,
}

impl WalletServiceBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self { manager: None }
    }

    /// Set the wallet manager
    pub fn with_manager(mut self, manager: Arc<WalletManager>) -> Self {
        self.manager = Some(manager);
        self
    }

    /// Build the wallet service
    pub fn build(self) -> Result<WalletServiceImpl, WalletError> {
        let manager = self
            .manager
            .ok_or_else(|| WalletError::InitializationError("Manager not set".to_string()))?;

        Ok(WalletServiceImpl::new(manager))
    }
}

impl Default for WalletServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;

    #[test]
    fn test_wallet_utxo_conversion() {
        let utxo = WalletUtxo {
            outpoint: OutPoint::null(),
            amount: Amount::from_sat(100_000),
            confirmations: 6,
            reserved: false,
        };

        let port_utxo: PortWalletUtxo = utxo.into();

        assert_eq!(port_utxo.amount.to_sat(), 100_000);
        assert_eq!(port_utxo.confirmations, 6);
        assert!(!port_utxo.reserved);
    }
}
