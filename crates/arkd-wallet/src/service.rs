//! WalletService trait implementation (stub — full impl on feat/wallet-service)

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;
use std::sync::Arc;

use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::{BlockTimestamp, TxInput, WalletService, WalletStatus};
use arkd_core::VtxoOutpoint;

use crate::manager::WalletManager;
use crate::WalletError;

/// Wallet service adapter
pub struct WalletServiceImpl {
    manager: Arc<WalletManager>,
}

impl WalletServiceImpl {
    /// Create new
    pub fn new(manager: Arc<WalletManager>) -> Self {
        Self { manager }
    }

    /// Get manager
    pub fn manager(&self) -> &Arc<WalletManager> {
        &self.manager
    }

    /// Sync wallet
    pub async fn sync(&self) -> ArkResult<()> {
        self.manager
            .sync()
            .await
            .map_err(|e| ArkError::WalletError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl WalletService for WalletServiceImpl {
    async fn status(&self) -> ArkResult<WalletStatus> {
        Ok(WalletStatus {
            initialized: true,
            unlocked: true,
            synced: true,
        })
    }

    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        Ok(self.manager.asp_pubkey())
    }

    async fn derive_connector_address(&self) -> ArkResult<String> {
        Err(ArkError::WalletError("Not yet implemented".to_string()))
    }

    async fn sign_transaction(&self, _partial_tx: &str, _extract_raw: bool) -> ArkResult<String> {
        Err(ArkError::WalletError("Not yet implemented".to_string()))
    }

    async fn select_utxos(
        &self,
        _amount: u64,
        _confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)> {
        Err(ArkError::WalletError("Not yet implemented".to_string()))
    }

    async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
        Err(ArkError::WalletError("Not yet implemented".to_string()))
    }

    async fn fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }

    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        Ok(BlockTimestamp {
            height: 0,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }

    async fn get_outpoint_status(&self, _outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        Ok(false)
    }
}

/// Builder for WalletServiceImpl
pub struct WalletServiceBuilder {
    manager: Option<Arc<WalletManager>>,
}

impl WalletServiceBuilder {
    /// New builder
    pub fn new() -> Self {
        Self { manager: None }
    }

    /// Set manager
    pub fn with_manager(mut self, manager: Arc<WalletManager>) -> Self {
        self.manager = Some(manager);
        self
    }

    /// Build
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
