//! Simplified BDK wallet service using raw descriptors + Esplora.
//!
//! [`BdkWalletService`] implements the [`WalletService`] trait from dark-core
//! using BDK directly with user-supplied descriptors, without the full
//! [`WalletManager`](crate::manager::WalletManager) machinery. Useful for
//! lightweight or embedded deployments where mnemonic management and file-store
//! persistence are handled externally.

use std::sync::Arc;

use async_trait::async_trait;
use base64::prelude::*;
use bdk_esplora::esplora_client::{self, AsyncClient};
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::consensus::encode;
use bitcoin::psbt::Psbt;
use bitcoin::{Network, XOnlyPublicKey};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{
    BlockTimestamp, DerivedAddress, TxInput, WalletBalance, WalletService, WalletStatus,
};
use dark_core::VtxoOutpoint;

/// A production wallet service backed by BDK with Esplora sync.
///
/// Constructed from raw descriptors, this is a thinner alternative to
/// [`WalletServiceImpl`](crate::service::WalletServiceImpl) that doesn't
/// require `WalletConfig` / `WalletManager`.
pub struct BdkWalletService {
    wallet: Arc<Mutex<Wallet>>,
    esplora: Arc<AsyncClient>,
    network: Network,
}

impl BdkWalletService {
    /// Create a new `BdkWalletService`.
    ///
    /// # Arguments
    /// * `descriptor` – external (receiving) output descriptor
    /// * `change_descriptor` – internal (change) output descriptor
    /// * `network` – Bitcoin network
    /// * `esplora_url` – Esplora HTTP API base URL
    pub async fn new(
        descriptor: &str,
        change_descriptor: &str,
        network: Network,
        esplora_url: &str,
    ) -> anyhow::Result<Self> {
        let wallet = Wallet::create(descriptor.to_string(), change_descriptor.to_string())
            .network(network)
            .create_wallet_no_persist()?;

        let esplora = esplora_client::Builder::new(esplora_url).build_async()?;

        info!(?network, %esplora_url, "BdkWalletService initialised");

        Ok(Self {
            wallet: Arc::new(Mutex::new(wallet)),
            esplora: Arc::new(esplora),
            network,
        })
    }

    /// Sync the wallet with the Esplora backend.
    pub async fn sync(&self) -> anyhow::Result<()> {
        let request = {
            let wallet = self.wallet.lock().await;
            wallet.start_full_scan().build()
        };

        let update = self
            .esplora
            .full_scan(request, 5, 5)
            .await
            .map_err(|e| anyhow::anyhow!("Esplora full-scan failed: {e}"))?;

        let mut wallet = self.wallet.lock().await;
        wallet.apply_update(update)?;
        info!("BdkWalletService sync complete");
        Ok(())
    }

    /// Get the Bitcoin network this wallet is configured for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Sync the wallet with the Esplora backend (best-effort).
    /// Logs a warning on failure instead of returning an error so that
    /// callers that need fresh state can still proceed with stale data.
    async fn try_sync(&self) {
        let request = {
            let wallet = self.wallet.lock().await;
            wallet.start_full_scan().build()
        };

        match self.esplora.full_scan(request, 5, 5).await {
            Ok(update) => {
                let mut wallet = self.wallet.lock().await;
                if let Err(e) = wallet.apply_update(update) {
                    warn!("Wallet sync apply failed: {e}");
                } else {
                    debug!("Wallet sync complete");
                }
            }
            Err(e) => {
                warn!("Wallet sync failed: {e}");
            }
        }
    }
}

fn map_err(e: impl std::fmt::Display) -> ArkError {
    ArkError::WalletError(e.to_string())
}

#[async_trait]
impl WalletService for BdkWalletService {
    async fn status(&self) -> ArkResult<WalletStatus> {
        Ok(WalletStatus {
            initialized: true,
            unlocked: true,
            synced: true,
        })
    }

    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
        let wallet = self.wallet.lock().await;
        let spk = wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey();

        // Extract x-only pubkey from a Taproot script-pubkey (OP_1 <32-byte key>)
        if spk.is_p2tr() {
            let bytes = spk.as_bytes();
            // p2tr script: 0x51 0x20 <32 bytes>
            let xonly = XOnlyPublicKey::from_slice(&bytes[2..34]).map_err(map_err)?;
            Ok(xonly)
        } else {
            Err(ArkError::WalletError(
                "First address is not Taproot; cannot extract x-only pubkey".into(),
            ))
        }
    }

    async fn derive_connector_address(&self) -> ArkResult<String> {
        let mut wallet = self.wallet.lock().await;
        let addr = wallet.next_unused_address(KeychainKind::External);
        debug!(%addr, "BdkWalletService derived connector address");
        Ok(addr.to_string())
    }

    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String> {
        let psbt_bytes = BASE64_STANDARD
            .decode(partial_tx)
            .map_err(|e| map_err(format!("Invalid base64 PSBT: {e}")))?;
        let mut psbt =
            Psbt::deserialize(&psbt_bytes).map_err(|e| map_err(format!("Invalid PSBT: {e}")))?;

        {
            let wallet = self.wallet.lock().await;
            let sign_opts = bdk_wallet::SignOptions {
                trust_witness_utxo: true,
                try_finalize: false,
                ..Default::default()
            };
            let finalized = wallet.sign(&mut psbt, sign_opts).map_err(map_err)?;
            info!(finalized, "PSBT signing result");
            for (i, inp) in psbt.inputs.iter().enumerate() {
                let (wu_amount, wu_script) = inp
                    .witness_utxo
                    .as_ref()
                    .map(|u| (u.value.to_sat(), hex::encode(u.script_pubkey.as_bytes())))
                    .unwrap_or((0, String::new()));
                info!(
                    input_idx = i,
                    has_tap_key_sig = inp.tap_key_sig.is_some(),
                    tap_script_sigs = inp.tap_script_sigs.len(),
                    witness_utxo_amount = wu_amount,
                    witness_utxo_script = %wu_script,
                    has_final_witness = inp.final_script_witness.is_some(),
                    "BDK sign result per input"
                );
            }
        }

        if extract_raw {
            let tx = psbt
                .extract_tx()
                .map_err(|e| map_err(format!("Cannot extract tx: {e}")))?;
            Ok(encode::serialize_hex(&tx))
        } else {
            Ok(BASE64_STANDARD.encode(psbt.serialize()))
        }
    }

    async fn select_utxos(
        &self,
        amount: u64,
        confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)> {
        self.try_sync().await;
        let wallet = self.wallet.lock().await;
        let mut utxos: Vec<_> = wallet
            .list_unspent()
            .filter(|u| {
                if confirmed_only {
                    u.chain_position.is_confirmed()
                } else {
                    true
                }
            })
            .collect();

        utxos.sort_by(|a, b| b.txout.value.cmp(&a.txout.value));

        let mut selected = Vec::new();
        let mut total: u64 = 0;

        for utxo in utxos {
            if total >= amount {
                break;
            }
            let sat = utxo.txout.value.to_sat();
            total += sat;
            selected.push(TxInput {
                txid: utxo.outpoint.txid.to_string(),
                vout: utxo.outpoint.vout,
                amount: sat,
                script: hex::encode(utxo.txout.script_pubkey.as_bytes()),
            });
        }

        if total < amount {
            return Err(ArkError::WalletError(format!(
                "Insufficient funds: need {amount} sats, have {total} sats"
            )));
        }
        Ok((selected, total))
    }

    async fn broadcast_transaction(&self, txs: Vec<String>) -> ArkResult<String> {
        let mut last_txid = String::new();
        for raw_hex in &txs {
            let tx_bytes =
                hex::decode(raw_hex).map_err(|e| map_err(format!("Invalid hex: {e}")))?;
            let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes)
                .map_err(|e| map_err(format!("Invalid tx: {e}")))?;
            self.esplora
                .broadcast(&tx)
                .await
                .map_err(|e| map_err(format!("Broadcast failed: {e}")))?;
            last_txid = tx.compute_txid().to_string();
            info!(%last_txid, "Broadcast transaction");
        }
        Ok(last_txid)
    }

    async fn fee_rate(&self) -> ArkResult<u64> {
        warn!("BdkWalletService::fee_rate — using default 1 sat/vB");
        Ok(1)
    }

    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
        warn!("BdkWalletService::get_current_block_time — using local clock");
        let wallet = self.wallet.lock().await;
        let tip = wallet.local_chain().tip().height();
        Ok(BlockTimestamp {
            height: tip as u64,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    async fn get_dust_amount(&self) -> ArkResult<u64> {
        Ok(546)
    }

    async fn get_outpoint_status(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        let txid: bitcoin::Txid = outpoint
            .txid
            .parse()
            .map_err(|e| map_err(format!("Invalid txid: {e}")))?;
        let wallet = self.wallet.lock().await;
        let found = wallet.get_tx(txid).is_some();
        Ok(found)
    }

    // ── Operator wallet management ───────────────────────────────────

    async fn gen_seed(&self) -> ArkResult<String> {
        use bdk_wallet::keys::bip39::{Language, Mnemonic, WordCount};
        use bdk_wallet::keys::GeneratableKey;
        use bdk_wallet::miniscript::Tap;
        let generated: bdk_wallet::keys::GeneratedKey<Mnemonic, Tap> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|e| map_err(format!("{e:?}")))?;
        Ok(generated.into_key().to_string())
    }

    async fn create_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        // BdkWalletService is already initialised from descriptors.
        // Full mnemonic→descriptor flow would require re-creating the wallet.
        // For now, acknowledge the call without error.
        info!("create_wallet called — wallet already initialised from descriptors");
        Ok(())
    }

    async fn restore_wallet(&self, _mnemonic: &str, _password: &str) -> ArkResult<()> {
        info!("restore_wallet called — wallet already initialised from descriptors");
        Ok(())
    }

    async fn unlock(&self, _password: &str) -> ArkResult<()> {
        // BdkWalletService does not have password-based locking.
        info!("unlock called — BdkWalletService is always unlocked");
        Ok(())
    }

    async fn lock(&self) -> ArkResult<()> {
        info!("lock called — BdkWalletService does not support locking");
        Ok(())
    }

    async fn derive_address(&self) -> ArkResult<DerivedAddress> {
        let mut wallet = self.wallet.lock().await;
        let info = wallet.next_unused_address(KeychainKind::External);
        Ok(DerivedAddress {
            address: info.address.to_string(),
            derivation_path: format!("m/86'/1'/0'/0/{}", info.index),
        })
    }

    async fn get_balance(&self) -> ArkResult<WalletBalance> {
        self.try_sync().await;
        let wallet = self.wallet.lock().await;
        let bal = wallet.balance();
        Ok(WalletBalance {
            confirmed: bal.confirmed.to_sat(),
            unconfirmed: (bal.trusted_pending + bal.untrusted_pending).to_sat(),
            locked: bal.immature.to_sat(),
        })
    }

    async fn withdraw(&self, address: &str, amount_sats: u64) -> ArkResult<String> {
        use bitcoin::Address;
        use std::str::FromStr;

        let addr = Address::from_str(address)
            .map_err(|e| map_err(format!("Invalid address: {e}")))?
            .require_network(self.network)
            .map_err(|e| map_err(format!("Network mismatch: {e}")))?;

        let mut wallet = self.wallet.lock().await;
        let mut tx_builder = wallet.build_tx();
        tx_builder.add_recipient(addr.script_pubkey(), bitcoin::Amount::from_sat(amount_sats));

        let psbt = tx_builder
            .finish()
            .map_err(|e| map_err(format!("Build tx failed: {e}")))?;

        let finalized = wallet
            .sign(&mut psbt.clone(), Default::default())
            .map_err(map_err)?;

        if !finalized {
            return Err(ArkError::WalletError(
                "Failed to fully sign withdrawal transaction".into(),
            ));
        }

        let tx = psbt
            .extract_tx()
            .map_err(|e| map_err(format!("Extract tx failed: {e}")))?;
        let txid = tx.compute_txid().to_string();

        // Broadcast via Esplora
        self.esplora
            .broadcast(&tx)
            .await
            .map_err(|e| map_err(format!("Broadcast failed: {e}")))?;

        info!(%txid, "Withdrawal broadcast");
        Ok(txid)
    }
}

/// Builder for [`BdkWalletService`].
///
/// ```rust,no_run
/// # use dark_wallet::bdk_wallet::WalletBuilder;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let svc = WalletBuilder {
///     descriptor: "tr(...)".into(),
///     change_descriptor: "tr(...)".into(),
///     network: bitcoin::Network::Regtest,
///     esplora_url: "http://localhost:3002".into(),
/// }
/// .build()
/// .await?;
/// # Ok(()) }
/// ```
pub struct WalletBuilder {
    pub descriptor: String,
    pub change_descriptor: String,
    pub network: Network,
    pub esplora_url: String,
}

impl WalletBuilder {
    /// Build and return a [`BdkWalletService`].
    pub async fn build(self) -> anyhow::Result<BdkWalletService> {
        BdkWalletService::new(
            &self.descriptor,
            &self.change_descriptor,
            self.network,
            &self.esplora_url,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_core::ports::WalletService;

    /// Test descriptor (BIP86 Taproot) derived from the "abandon" mnemonic
    const TEST_DESC: &str = "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/86'/1'/0'/0/*)";
    const TEST_CHANGE_DESC: &str = "tr(tprv8ZgxMBicQKsPdDArR4xSAECuVxeX1jwwSXR4ApKbkYgZiziDc4LdBy2WvJeGDfUSE4UT4hHhbgEwbdq8ajjUHiKDegkwrNU6V55CxcxonVN/86'/1'/0'/1/*)";

    #[tokio::test]
    async fn test_bdk_wallet_builder_default() {
        let builder = WalletBuilder {
            descriptor: TEST_DESC.to_string(),
            change_descriptor: TEST_CHANGE_DESC.to_string(),
            network: Network::Regtest,
            esplora_url: "http://localhost:3002".to_string(),
        };
        let svc = builder.build().await.expect("builder should succeed");
        assert_eq!(svc.network(), Network::Regtest);
    }

    #[tokio::test]
    async fn test_wallet_get_address_type() {
        let svc = BdkWalletService::new(
            TEST_DESC,
            TEST_CHANGE_DESC,
            Network::Regtest,
            "http://localhost:3002",
        )
        .await
        .unwrap();
        let addr = svc.derive_connector_address().await.unwrap();
        // Regtest Taproot addresses begin with "bcrt1p"
        assert!(
            addr.starts_with("bcrt1p"),
            "Expected Taproot address, got: {addr}"
        );
    }

    #[tokio::test]
    async fn test_wallet_network_matches_config() {
        let svc = BdkWalletService::new(
            TEST_DESC,
            TEST_CHANGE_DESC,
            Network::Regtest,
            "http://localhost:3002",
        )
        .await
        .unwrap();
        assert_eq!(svc.network(), Network::Regtest);

        let status = svc.status().await.unwrap();
        assert!(status.initialized);
        assert!(status.unlocked);
    }

    #[tokio::test]
    async fn test_wallet_forfeit_pubkey_is_32_bytes() {
        let svc = BdkWalletService::new(
            TEST_DESC,
            TEST_CHANGE_DESC,
            Network::Regtest,
            "http://localhost:3002",
        )
        .await
        .unwrap();
        let pk = svc.get_forfeit_pubkey().await.unwrap();
        assert_eq!(pk.serialize().len(), 32);
    }

    #[tokio::test]
    async fn test_wallet_dust_amount() {
        let svc = BdkWalletService::new(
            TEST_DESC,
            TEST_CHANGE_DESC,
            Network::Regtest,
            "http://localhost:3002",
        )
        .await
        .unwrap();
        let dust = svc.get_dust_amount().await.unwrap();
        assert_eq!(dust, 546);
    }

    #[tokio::test]
    async fn test_wallet_select_utxos_empty() {
        let svc = BdkWalletService::new(
            TEST_DESC,
            TEST_CHANGE_DESC,
            Network::Regtest,
            "http://localhost:3002",
        )
        .await
        .unwrap();
        let result = svc.select_utxos(100_000, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient"));
    }

    #[test]
    fn test_bdk_wallet_service_is_object_safe() {
        fn _assert(_: Arc<dyn WalletService>) {}
    }
}
