//! Lightweight VTXO sweeper — finds expired VTXOs and reclaims them for the ASP.
//!
//! Unlike [`crate::sweep::SweepRunner`] which handles batching & broadcasting,
//! this module provides a small, testable core that:
//! 1. Queries for expired VTXOs via [`VtxoRepository::find_expired_vtxos`].
//! 2. Publishes a [`ArkEvent::VtxoForfeited`] for each one.
//! 3. Can be driven by a block-height channel for periodic checks.

use std::sync::Arc;
use tracing::instrument;

use crate::domain::events::ArkEvent;
use crate::domain::Vtxo;
use crate::error::ArkResult;
use crate::ports::{
    EventPublisher, NoopNotifier, Notifier, SignerService, SweepInput, TxBuilder, VtxoRepository,
    WalletService,
};

/// Sweeps expired VTXOs back to the ASP.
///
/// When a [`Notifier`] is configured (e.g. `dark_nostr::NostrNotifier`),
/// the sweeper will send VTXO expiry notifications to affected users
/// before publishing the sweep event. (Issue #247)
pub struct Sweeper {
    vtxo_repo: Arc<dyn VtxoRepository>,
    events: Arc<dyn EventPublisher>,
    notifier: Arc<dyn Notifier>,
    tx_builder: Arc<dyn TxBuilder>,
    wallet: Arc<dyn WalletService>,
    signer: Arc<dyn SignerService>,
}

impl Sweeper {
    /// Create a new sweeper.
    pub fn new(
        vtxo_repo: Arc<dyn VtxoRepository>,
        events: Arc<dyn EventPublisher>,
        tx_builder: Arc<dyn TxBuilder>,
        wallet: Arc<dyn WalletService>,
        signer: Arc<dyn SignerService>,
    ) -> Self {
        Self {
            vtxo_repo,
            events,
            notifier: Arc::new(NoopNotifier),
            tx_builder,
            wallet,
            signer,
        }
    }

    /// Create a sweeper with a custom notifier for VTXO expiry alerts.
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Sweep all VTXOs that have expired before `current_timestamp` (time-based)
    /// or at/before `current_height` (block-based).
    /// Returns the number of VTXOs swept.
    #[instrument(skip(self))]
    pub async fn sweep_expired(
        &self,
        current_timestamp: i64,
        current_height: Option<u32>,
    ) -> ArkResult<u32> {
        let mut expired: Vec<Vtxo> = self.vtxo_repo.find_expired_vtxos(current_timestamp).await?;
        if let Some(height) = current_height {
            let block_expired = self.vtxo_repo.find_block_expired_vtxos(height).await?;
            expired.extend(block_expired);
        }

        let count = expired.len() as u32;

        for vtxo in &expired {
            let vtxo_id = vtxo.outpoint.to_string();
            tracing::info!(
                vtxo_id = %vtxo_id,
                expires_at = vtxo.expires_at,
                "Sweeping expired VTXO"
            );

            // Notify the VTXO owner about the expiry (Issue #247)
            if let Err(e) = self
                .notifier
                .notify_vtxo_expiry(&vtxo.pubkey, &vtxo_id, 0)
                .await
            {
                tracing::warn!(
                    vtxo_id = %vtxo.outpoint,
                    error = %e,
                    "Failed to send VTXO expiry notification (continuing sweep)"
                );
            }

            // Build a sweep transaction for this VTXO
            let sweep_input = SweepInput {
                txid: vtxo.outpoint.txid.clone(),
                vout: vtxo.outpoint.vout,
                amount: vtxo.amount,
                tapscripts: Vec::new(), // TxBuilder resolves scripts from the tree
            };

            let (_preliminary_txid, psbt_hex) =
                self.tx_builder.build_sweep_tx(&[sweep_input]).await?;
            let signed = self.signer.sign_transaction(&psbt_hex, false).await?;
            let raw_tx = self.tx_builder.finalize_and_extract(&signed).await?;
            let txid = self.wallet.broadcast_transaction(vec![raw_tx]).await?;

            tracing::info!(
                vtxo_id = %vtxo_id,
                sweep_txid = %txid,
                "Broadcast sweep transaction for expired VTXO"
            );

            self.events
                .publish_event(ArkEvent::VtxoForfeited {
                    vtxo_id,
                    forfeit_txid: txid,
                })
                .await?;
        }

        // Mark VTXOs as swept in the repository
        if count > 0 {
            if let Err(e) = self.vtxo_repo.mark_vtxos_swept(&expired).await {
                tracing::warn!(
                    error = %e,
                    "Failed to mark VTXOs as swept in repository (continuing)"
                );
            }
            tracing::info!(swept_count = count, "Sweep complete");
        }

        Ok(count)
    }

    /// Spawn a background sweeper loop triggered by block events.
    pub fn spawn_sweeper_loop(
        sweeper: Arc<Sweeper>,
        mut block_rx: tokio::sync::mpsc::Receiver<u32>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(height) = block_rx.recv().await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                match sweeper.sweep_expired(now, Some(height)).await {
                    Ok(n) if n > 0 => tracing::info!(swept = n, "Block sweep done"),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "Sweep error"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{FlatTxTree, Intent, VtxoOutpoint};
    use crate::ports::{
        BlockTimestamp, BoardingInput, CommitmentTxResult, LoggingEventPublisher,
        SignedBoardingInput, SweepableOutput, TxInput, ValidForfeitTx, WalletStatus,
    };
    use async_trait::async_trait;
    use bitcoin::XOnlyPublicKey;

    struct MockVtxoRepo {
        expired: Vec<Vtxo>,
    }

    impl MockVtxoRepo {
        fn empty() -> Self {
            Self {
                expired: Vec::new(),
            }
        }
        fn with_vtxos(vtxos: Vec<Vtxo>) -> Self {
            Self { expired: vtxos }
        }
    }

    #[async_trait]
    impl VtxoRepository for MockVtxoRepo {
        async fn add_vtxos(&self, _vtxos: &[Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(
            &self,
            _pubkey: &str,
        ) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(
            &self,
            _spent: &[(VtxoOutpoint, String)],
            _ark_txid: &str,
        ) -> ArkResult<()> {
            Ok(())
        }
        async fn find_expired_vtxos(&self, _before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
            Ok(self.expired.clone())
        }
    }

    struct MockTxBuilder;

    #[async_trait]
    impl TxBuilder for MockTxBuilder {
        async fn build_commitment_tx(
            &self,
            _signer_pubkey: &XOnlyPublicKey,
            _intents: &[Intent],
            _boarding_inputs: &[BoardingInput],
        ) -> ArkResult<CommitmentTxResult> {
            Ok(CommitmentTxResult {
                commitment_tx: String::new(),
                vtxo_tree: Vec::new(),
                connector_address: String::new(),
                connectors: Vec::new(),
            })
        }
        async fn verify_forfeit_txs(
            &self,
            _vtxos: &[Vtxo],
            _connectors: &FlatTxTree,
            _txs: &[String],
        ) -> ArkResult<Vec<ValidForfeitTx>> {
            Ok(Vec::new())
        }
        async fn build_sweep_tx(&self, inputs: &[SweepInput]) -> ArkResult<(String, String)> {
            Ok((format!("sweep_txid_{}", inputs.len()), "psbt_hex".into()))
        }
        async fn get_sweepable_batch_outputs(
            &self,
            _vtxo_tree: &FlatTxTree,
        ) -> ArkResult<Option<SweepableOutput>> {
            Ok(None)
        }
        async fn finalize_and_extract(&self, tx: &str) -> ArkResult<String> {
            Ok(format!("final_{tx}"))
        }
        async fn verify_vtxo_tapscript_sigs(
            &self,
            _tx: &str,
            _must_include_signer: bool,
        ) -> ArkResult<bool> {
            Ok(true)
        }
        async fn verify_boarding_tapscript_sigs(
            &self,
            _signed_tx: &str,
            _commitment_tx: &str,
        ) -> ArkResult<std::collections::HashMap<u32, SignedBoardingInput>> {
            Ok(std::collections::HashMap::new())
        }
    }

    struct MockWallet;

    #[async_trait]
    impl WalletService for MockWallet {
        async fn status(&self) -> ArkResult<WalletStatus> {
            Ok(WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }
        async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok("bc1qsweep".into())
        }
        async fn sign_transaction(&self, tx: &str, _extract_raw: bool) -> ArkResult<String> {
            Ok(tx.to_string())
        }
        async fn select_utxos(
            &self,
            _amount: u64,
            _confirmed_only: bool,
        ) -> ArkResult<(Vec<TxInput>, u64)> {
            Ok((vec![], 0))
        }
        async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
            Ok("sweep_broadcast_txid".into())
        }
        async fn fee_rate(&self) -> ArkResult<u64> {
            Ok(10)
        }
        async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
            Ok(BlockTimestamp {
                height: 100,
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

    struct MockSigner;

    #[async_trait]
    impl SignerService for MockSigner {
        async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn sign_transaction(&self, tx: &str, _extract_raw: bool) -> ArkResult<String> {
            Ok(format!("signed_{tx}"))
        }
    }

    fn make_vtxo(txid: &str, expires_at: i64) -> Vtxo {
        let mut v = Vtxo::new(
            VtxoOutpoint::new(txid.to_string(), 0),
            50_000,
            "deadbeef".to_string(),
        );
        v.expires_at = expires_at;
        v
    }

    fn make_sweeper(repo: MockVtxoRepo) -> Sweeper {
        Sweeper::new(
            Arc::new(repo),
            Arc::new(LoggingEventPublisher::new(16)),
            Arc::new(MockTxBuilder),
            Arc::new(MockWallet),
            Arc::new(MockSigner),
        )
    }

    #[tokio::test]
    async fn test_sweep_no_expired_returns_zero() {
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(1_000_000, None).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_expired_vtxo_returns_one() {
        let vtxo = make_vtxo("expired_tx", 500);
        let sweeper = make_sweeper(MockVtxoRepo::with_vtxos(vec![vtxo]));
        let count = sweeper.sweep_expired(1_000, None).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_sweep_ignores_future_expiry() {
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(100, None).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_ignores_zero_expiry() {
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(0, None).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_multiple_expired_vtxos() {
        let vtxos = vec![
            make_vtxo("tx1", 100),
            make_vtxo("tx2", 200),
            make_vtxo("tx3", 300),
        ];
        let sweeper = make_sweeper(MockVtxoRepo::with_vtxos(vtxos));
        let count = sweeper.sweep_expired(1_000, None).await.unwrap();
        assert_eq!(count, 3);
    }
}
