//! WalletService trait implementation backed by BDK WalletManager
//!
//! Provides a concrete implementation of the [`WalletService`] port from dark-core,
//! wiring all wallet operations through the BDK-based [`WalletManager`].

use async_trait::async_trait;
use base64::prelude::*;
use bitcoin::consensus::encode;
use bitcoin::psbt::Psbt;
use bitcoin::XOnlyPublicKey;
use std::sync::Arc;
use tracing::{debug, info};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{BlockTimestamp, TxInput, WalletService, WalletStatus};
use dark_core::VtxoOutpoint;

use crate::manager::WalletManager;
use crate::WalletError;

/// Wallet service adapter — bridges dark-core's [`WalletService`] port to BDK
pub struct WalletServiceImpl {
    manager: Arc<WalletManager>,
}

impl WalletServiceImpl {
    /// Create a new wallet service from a wallet manager
    pub fn new(manager: Arc<WalletManager>) -> Self {
        Self { manager }
    }

    /// Get a reference to the underlying wallet manager
    pub fn manager(&self) -> &Arc<WalletManager> {
        &self.manager
    }

    /// Sync wallet with the blockchain via Esplora
    pub async fn sync(&self) -> ArkResult<()> {
        self.manager
            .sync()
            .await
            .map_err(|e| ArkError::WalletError(e.to_string()))?;
        Ok(())
    }
}

fn map_wallet_err(e: impl std::fmt::Display) -> ArkError {
    ArkError::WalletError(e.to_string())
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
        let address = self
            .manager
            .get_new_address()
            .await
            .map_err(map_wallet_err)?;
        debug!(%address, "Derived connector address");
        Ok(address.to_string())
    }

    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String> {
        let psbt_bytes = BASE64_STANDARD
            .decode(partial_tx)
            .map_err(|e| map_wallet_err(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| map_wallet_err(format!("Invalid PSBT: {e}")))?;

        self.manager
            .sign_psbt(&mut psbt)
            .await
            .map_err(map_wallet_err)?;

        if extract_raw {
            let tx = psbt
                .extract_tx()
                .map_err(|e| map_wallet_err(format!("Cannot extract tx: {e}")))?;
            let raw = encode::serialize_hex(&tx);
            info!("Signed and extracted raw transaction");
            Ok(raw)
        } else {
            let signed = psbt.serialize();
            Ok(BASE64_STANDARD.encode(&signed))
        }
    }

    async fn select_utxos(
        &self,
        amount: u64,
        confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)> {
        let min_conf = if confirmed_only {
            self.manager.config().min_confirmations
        } else {
            0
        };
        let utxos = self
            .manager
            .get_unreserved_utxos(min_conf)
            .await
            .map_err(map_wallet_err)?;

        let mut selected = Vec::new();
        let mut total: u64 = 0;

        // Simple largest-first selection
        let mut sorted_utxos = utxos;
        sorted_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in sorted_utxos {
            if total >= amount {
                break;
            }
            total += utxo.amount.to_sat();
            selected.push(TxInput {
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount: utxo.amount.to_sat(),
                script: String::new(), // Script not needed for PSBT workflow
            });
            // Reserve selected UTXOs
            let _ = self.manager.reserve_utxo(utxo.outpoint).await;
        }

        if total < amount {
            return Err(ArkError::WalletError(format!(
                "Insufficient funds: need {amount} sats, have {total} sats"
            )));
        }

        debug!(
            selected_count = selected.len(),
            total_sats = total,
            "Selected UTXOs for {amount} sats"
        );
        Ok((selected, total))
    }

    async fn broadcast_transaction(&self, txs: Vec<String>) -> ArkResult<String> {
        let mut last_txid = String::new();
        for raw_hex in &txs {
            let tx_bytes = hex::decode(raw_hex)
                .map_err(|e| map_wallet_err(format!("Invalid hex transaction: {e}")))?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|e| map_wallet_err(format!("Invalid transaction: {e}")))?;
            let txid = self
                .manager
                .broadcast_transaction(&tx)
                .await
                .map_err(map_wallet_err)?;
            last_txid = txid.to_string();
            info!(%txid, "Broadcast transaction");
        }
        Ok(last_txid)
    }

    async fn fee_rate(&self) -> ArkResult<u64> {
        // Default fee rate — in production, query from Esplora mempool
        Ok(1)
    }

    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        let height = self.manager.current_height().await;
        Ok(BlockTimestamp {
            height: height as u64,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    async fn get_dust_amount(&self) -> ArkResult<u64> {
        // Standard dust limit for Taproot outputs
        Ok(546)
    }

    async fn get_outpoint_status(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        let txid: bitcoin::Txid = outpoint
            .txid
            .parse()
            .map_err(|e| map_wallet_err(format!("Invalid txid: {e}")))?;
        // Check if we can find the transaction in the wallet's graph
        let tx = self
            .manager
            .get_transaction(txid)
            .await
            .map_err(map_wallet_err)?;
        Ok(tx.is_some())
    }

    async fn add_fee_input(&self, psbt_base64: &str, fee_amount: u64) -> ArkResult<String> {
        // Decode the base64 PSBT
        let psbt_bytes = BASE64_STANDARD
            .decode(psbt_base64)
            .map_err(|e| map_wallet_err(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| map_wallet_err(format!("Invalid PSBT: {e}")))?;

        // Add the fee input using BDK's TxBuilder (ensures proper PSBT metadata for signing)
        self.manager
            .add_fee_input_to_psbt(&mut psbt, fee_amount)
            .await
            .map_err(map_wallet_err)?;

        // Return the modified PSBT
        Ok(BASE64_STANDARD.encode(psbt.serialize()))
    }

    async fn manual_sign_fee_input(&self, psbt_base64: &str) -> ArkResult<String> {
        // Decode the base64 PSBT
        let psbt_bytes = BASE64_STANDARD
            .decode(psbt_base64)
            .map_err(|e| map_wallet_err(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt = Psbt::deserialize(&psbt_bytes)
            .map_err(|e| map_wallet_err(format!("Invalid PSBT: {e}")))?;

        // The fee input is always the last input
        let fee_input_idx = psbt.inputs.len().saturating_sub(1);

        // Manually sign the fee input
        self.manager
            .manual_sign_fee_input(&mut psbt, fee_input_idx)
            .await
            .map_err(map_wallet_err)?;

        // Return the signed PSBT
        Ok(BASE64_STANDARD.encode(psbt.serialize()))
    }

    async fn derive_address(&self) -> ArkResult<dark_core::ports::DerivedAddress> {
        let address = self
            .manager
            .get_new_address()
            .await
            .map_err(map_wallet_err)?;
        Ok(dark_core::ports::DerivedAddress {
            address: address.to_string(),
            derivation_path: "m/86'/1'/0'/0/*".to_string(),
        })
    }

    async fn get_balance(&self) -> ArkResult<dark_core::ports::WalletBalance> {
        if let Err(e) = self.manager.sync().await {
            tracing::warn!(error = %e, "Wallet sync failed before get_balance");
        }
        let bal = self.manager.get_balance().await.map_err(map_wallet_err)?;
        Ok(dark_core::ports::WalletBalance {
            confirmed: bal.confirmed.to_sat(),
            unconfirmed: (bal.trusted_pending + bal.untrusted_pending).to_sat(),
            locked: 0,
        })
    }

    async fn gen_seed(&self) -> ArkResult<String> {
        use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
        use bdk_wallet::keys::GeneratableKey;
        use bdk_wallet::miniscript::Tap;
        let m: bdk_wallet::keys::GeneratedKey<Mnemonic, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|e| dark_core::error::ArkError::WalletError(format!("{e:?}")))?;
        Ok(m.into_key().to_string())
    }

    async fn create_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        info!("create_wallet called — WalletManager already initialised");
        Ok(())
    }

    async fn unlock(&self, _password: &str) -> ArkResult<()> {
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WalletConfig;
    use dark_core::ports::WalletService;
    use std::sync::Arc;
    use tempfile::TempDir;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Helper: create a WalletServiceImpl backed by a temp-dir BDK wallet
    async fn make_test_service() -> (WalletServiceImpl, TempDir) {
        let tmp = TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("wallet.db");
        let config = WalletConfig::regtest(db_path.to_str().unwrap()).with_mnemonic(TEST_MNEMONIC);
        let manager = Arc::new(WalletManager::new(config).await.expect("wallet manager"));
        let svc = WalletServiceBuilder::new()
            .with_manager(manager)
            .build()
            .expect("build service");
        (svc, tmp)
    }

    #[test]
    fn test_wallet_config_default_values() {
        let config = WalletConfig::default();
        assert_eq!(config.network, bitcoin::Network::Regtest);
        assert_eq!(config.database_path, "./data/wallet.db");
        assert_eq!(config.gap_limit, 20);
        assert!(config.esplora_url.is_some());
    }

    #[tokio::test]
    async fn test_wallet_service_builder_creates_instance() {
        let (svc, _tmp) = make_test_service().await;
        // Service is constructed — manager is accessible
        assert!(svc.manager().config().mnemonic.is_some());
    }

    #[test]
    fn test_wallet_service_builder_fails_without_manager() {
        let result = WalletServiceBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_implements_wallet_service_trait() {
        // Compile-time check: WalletServiceImpl can be used as Arc<dyn WalletService>
        fn _assert_trait_object(_: Arc<dyn WalletService>) {}
    }

    #[tokio::test]
    async fn test_wallet_get_address_returns_valid_bech32() {
        let (svc, _tmp) = make_test_service().await;
        let addr = svc.derive_connector_address().await.expect("address");
        // Regtest bech32m addresses start with "bcrt1p" (Taproot)
        assert!(
            addr.starts_with("bcrt1p"),
            "Expected regtest Taproot address, got: {addr}"
        );
    }

    #[tokio::test]
    async fn test_wallet_network_regtest() {
        let (svc, _tmp) = make_test_service().await;
        assert_eq!(svc.manager().config().network, bitcoin::Network::Regtest);
    }

    #[tokio::test]
    async fn test_wallet_status_returns_initialized() {
        let (svc, _tmp) = make_test_service().await;
        let status = svc.status().await.expect("status");
        assert!(status.initialized);
        assert!(status.unlocked);
        assert!(status.synced);
    }

    #[tokio::test]
    async fn test_wallet_get_forfeit_pubkey() {
        let (svc, _tmp) = make_test_service().await;
        let pubkey = svc.get_forfeit_pubkey().await.expect("pubkey");
        // X-only pubkey should be 32 bytes
        assert_eq!(pubkey.serialize().len(), 32);
    }

    #[tokio::test]
    async fn test_wallet_fee_rate() {
        let (svc, _tmp) = make_test_service().await;
        let rate = svc.fee_rate().await.expect("fee rate");
        assert_eq!(rate, 1);
    }

    #[tokio::test]
    async fn test_wallet_dust_amount() {
        let (svc, _tmp) = make_test_service().await;
        let dust = svc.get_dust_amount().await.expect("dust");
        assert_eq!(dust, 546);
    }

    #[tokio::test]
    async fn test_wallet_get_current_block_time() {
        let (svc, _tmp) = make_test_service().await;
        let bt = svc.get_current_block_time().await.expect("block time");
        // Timestamp should be recent (within last 10 seconds)
        let now = chrono::Utc::now().timestamp();
        assert!((now - bt.timestamp).abs() < 10);
    }

    #[tokio::test]
    async fn test_wallet_select_utxos_insufficient_funds() {
        let (svc, _tmp) = make_test_service().await;
        // Empty wallet — selecting any amount should fail
        let result = svc.select_utxos(1_000_000, true).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Insufficient funds"), "Got: {err_msg}");
    }

    #[tokio::test]
    async fn test_wallet_deterministic_pubkey() {
        // Same mnemonic should produce same ASP pubkey
        let (svc1, _tmp1) = make_test_service().await;
        let (svc2, _tmp2) = make_test_service().await;
        let pk1 = svc1.get_forfeit_pubkey().await.unwrap();
        let pk2 = svc2.get_forfeit_pubkey().await.unwrap();
        assert_eq!(pk1, pk2, "Same mnemonic should yield same ASP pubkey");
    }

    #[tokio::test]
    async fn test_add_fee_input_insufficient_funds() {
        // Empty wallet — add_fee_input should fail with insufficient funds
        let (svc, _tmp) = make_test_service().await;

        // Create a minimal PSBT (just needs to be valid base64 for the test)
        let dummy_psbt = bitcoin::psbt::Psbt::from_unsigned_tx(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(10_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        })
        .unwrap();
        let psbt_base64 = BASE64_STANDARD.encode(dummy_psbt.serialize());

        // Attempt to add a fee input to an empty wallet
        let result = svc.add_fee_input(&psbt_base64, 1_000).await;
        assert!(result.is_err(), "Should fail with insufficient funds");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Insufficient") || err_msg.contains("insufficient"),
            "Error should mention insufficient funds, got: {err_msg}"
        );
    }
}
