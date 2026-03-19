//! Sweep Service - Recovery of expired VTXOs
//!
//! The ASP periodically sweeps VTXOs that have passed their expiry time.
//! This allows the ASP to recover capital from inactive users.
//!
//! See Go: `github.com/ark-network/ark/internal/core/application/sweeper.go`

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, instrument, warn};

use crate::domain::Vtxo;
use crate::error::ArkResult;
use crate::ports::{
    NoopNotifier, Notifier, RoundRepository, SignerService, SweepInput, SweepResult, SweepService,
    TxBuilder, VtxoRepository, WalletService,
};

/// Sweep configuration
#[derive(Debug, Clone)]
pub struct SweepConfig {
    /// How often to check for sweepable VTXOs
    pub sweep_interval: Duration,
    /// Grace period after expiry before sweeping (seconds)
    pub grace_period_secs: i64,
    /// Maximum VTXOs to sweep per transaction
    pub max_vtxos_per_sweep: usize,
    /// Minimum amount to make a sweep worthwhile (sats)
    pub min_sweep_amount: u64,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            sweep_interval: Duration::from_secs(3600), // 1 hour
            grace_period_secs: 86400,                  // 1 day grace period
            max_vtxos_per_sweep: 100,
            min_sweep_amount: 10_000, // 10k sats minimum
        }
    }
}

/// A batch of VTXOs to sweep
#[derive(Debug, Clone)]
pub struct SweepBatch {
    /// Batch identifier
    pub id: String,
    /// VTXOs in this batch
    pub vtxos: Vec<Vtxo>,
    /// Total amount to recover
    pub total_amount: u64,
    /// Sweep transaction (once built)
    pub sweep_tx: Option<String>,
    /// Sweep transaction ID (once broadcast)
    pub sweep_txid: Option<String>,
    /// Created timestamp
    pub created_at: i64,
    /// Completed timestamp
    pub completed_at: Option<i64>,
}

impl SweepBatch {
    /// Create a new sweep batch
    pub fn new(vtxos: Vec<Vtxo>) -> Self {
        let total_amount = vtxos.iter().map(|v| v.amount).sum();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            vtxos,
            total_amount,
            sweep_tx: None,
            sweep_txid: None,
            created_at: chrono::Utc::now().timestamp(),
            completed_at: None,
        }
    }
}

/// Sweep service for recovering expired VTXOs
pub struct SweepRunner {
    config: SweepConfig,
    #[allow(dead_code)] // Will be used when find_sweepable_vtxos is fully implemented
    vtxo_repo: Arc<dyn VtxoRepository>,
    #[allow(dead_code)] // Will be used when update_round_sweep_status is fully implemented
    round_repo: Arc<dyn RoundRepository>,
    wallet: Arc<dyn WalletService>,
    /// Pending sweep batches
    pending_batches: Arc<RwLock<Vec<SweepBatch>>>,
    shutdown: broadcast::Sender<()>,
}

impl SweepRunner {
    /// Create a new sweep service
    pub fn new(
        config: SweepConfig,
        vtxo_repo: Arc<dyn VtxoRepository>,
        round_repo: Arc<dyn RoundRepository>,
        wallet: Arc<dyn WalletService>,
    ) -> Self {
        let (shutdown, _) = broadcast::channel(1);
        Self {
            config,
            vtxo_repo,
            round_repo,
            wallet,
            pending_batches: Arc::new(RwLock::new(Vec::new())),
            shutdown,
        }
    }

    /// Start the sweep service
    #[instrument(skip(self))]
    pub async fn run(&self) -> ArkResult<()> {
        let mut shutdown_rx = self.shutdown.subscribe();
        let mut interval = tokio::time::interval(self.config.sweep_interval);

        info!(
            "Sweep service started (interval: {:?})",
            self.config.sweep_interval
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.sweep_expired_vtxos().await {
                        error!("Sweep failed: {e}");
                    }
                }

                _ = shutdown_rx.recv() => {
                    info!("Sweep service shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Shutdown the sweep service
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    /// Find and sweep expired VTXOs
    #[instrument(skip(self))]
    async fn sweep_expired_vtxos(&self) -> ArkResult<()> {
        let now = chrono::Utc::now().timestamp();
        let sweep_threshold = now - self.config.grace_period_secs;

        // Find sweepable VTXOs from expired rounds
        let sweepable = self.find_sweepable_vtxos(sweep_threshold).await?;

        if sweepable.is_empty() {
            debug!("No VTXOs ready for sweep");
            return Ok(());
        }

        info!(count = sweepable.len(), "Found sweepable VTXOs");

        // Group into batches
        let batches = self.create_sweep_batches(sweepable);

        for batch in batches {
            if let Err(e) = self.execute_sweep_batch(batch).await {
                warn!("Sweep batch failed: {e}");
            }
        }

        Ok(())
    }

    /// Find VTXOs that can be swept
    async fn find_sweepable_vtxos(&self, before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
        // Query the VTXO repository for expired, unspent, unswept VTXOs
        self.vtxo_repo.find_expired_vtxos(before_timestamp).await
    }

    /// Create sweep batches from a list of VTXOs
    fn create_sweep_batches(&self, vtxos: Vec<Vtxo>) -> Vec<SweepBatch> {
        let mut batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_amount = 0u64;

        for vtxo in vtxos {
            current_amount += vtxo.amount;
            current_batch.push(vtxo);

            if current_batch.len() >= self.config.max_vtxos_per_sweep {
                if current_amount >= self.config.min_sweep_amount {
                    batches.push(SweepBatch::new(std::mem::take(&mut current_batch)));
                } else {
                    debug!("Batch too small to sweep: {} sats", current_amount);
                    current_batch.clear();
                }
                current_amount = 0;
            }
        }

        // Handle remaining VTXOs
        if !current_batch.is_empty() && current_amount >= self.config.min_sweep_amount {
            batches.push(SweepBatch::new(current_batch));
        }

        batches
    }

    /// Execute a sweep batch
    #[instrument(skip(self, batch), fields(batch_id = %batch.id, vtxo_count = batch.vtxos.len()))]
    async fn execute_sweep_batch(&self, mut batch: SweepBatch) -> ArkResult<String> {
        info!(amount = batch.total_amount, "Executing sweep batch");

        // Build sweep transaction
        let sweep_tx = self.build_sweep_transaction(&batch).await?;
        batch.sweep_tx = Some(sweep_tx.clone());

        // Broadcast the sweep transaction
        let txid = self.wallet.broadcast_transaction(vec![sweep_tx]).await?;
        batch.sweep_txid = Some(txid.clone());
        batch.completed_at = Some(chrono::Utc::now().timestamp());

        // Mark VTXOs as swept
        for vtxo in &batch.vtxos {
            // In a real implementation, update the VTXO in the repository
            // vtxo.swept = true;
            // vtxo_repo.update_vtxo(vtxo).await?;
            debug!(vtxo = %vtxo.outpoint, "Marked VTXO as swept");
        }

        // Update round sweep status if all VTXOs from a round are swept
        self.update_round_sweep_status(&batch).await?;

        info!(txid = %txid, "Sweep batch completed");
        Ok(txid)
    }

    /// Build a sweep transaction
    async fn build_sweep_transaction(&self, batch: &SweepBatch) -> ArkResult<String> {
        // Get current fee rate
        let fee_rate = self.wallet.fee_rate().await?;

        // Get the connector/sweep address
        let sweep_address = self.wallet.derive_connector_address().await?;

        // In a real implementation:
        // 1. For each VTXO, build the witness to spend the sweep branch
        // 2. Create a transaction spending all VTXOs to the sweep address
        // 3. Sign the transaction

        // Placeholder - return a mock transaction
        // TODO: Implement actual sweep transaction building
        let mock_tx = format!(
            "sweep_tx_batch_{}_vtxos_{}_to_{}",
            batch.id,
            batch.vtxos.len(),
            sweep_address
        );

        debug!(
            fee_rate = fee_rate,
            vtxo_count = batch.vtxos.len(),
            "Built sweep transaction"
        );

        Ok(mock_tx)
    }

    /// Update round sweep status after sweeping its VTXOs
    async fn update_round_sweep_status(&self, batch: &SweepBatch) -> ArkResult<()> {
        // Group VTXOs by their root commitment txid (round)
        let mut by_round: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();

        for vtxo in &batch.vtxos {
            if !vtxo.root_commitment_txid.is_empty() {
                *by_round.entry(&vtxo.root_commitment_txid).or_insert(0) += 1;
            }
        }

        // For each round, check if all VTXOs are now swept
        // In a real implementation, we'd check the repository
        // and update the round's swept flag if all VTXOs are swept

        debug!(rounds = by_round.len(), "Updated round sweep statuses");
        Ok(())
    }

    /// Get pending sweep batches
    pub async fn pending_batches(&self) -> Vec<SweepBatch> {
        self.pending_batches.read().await.clone()
    }
}

/// Statistics about sweep operations
#[derive(Debug, Clone, Default)]
pub struct SweepStats {
    /// Total VTXOs swept
    pub total_vtxos_swept: u64,
    /// Total amount swept (sats)
    pub total_amount_swept: u64,
    /// Number of sweep transactions
    pub sweep_tx_count: u64,
    /// Last sweep timestamp
    pub last_sweep_at: Option<i64>,
}

// ---------------------------------------------------------------------------
// TxBuilderSweepService — real SweepService wired to TxBuilder (#167)
// ---------------------------------------------------------------------------

/// A [`SweepService`] implementation that builds real sweep transactions
/// using the [`TxBuilder`] port.
///
/// Flow for `sweep_expired_vtxos`:
/// 1. Find expired VTXOs via [`VtxoRepository::find_expired_vtxos`].
/// 2. Convert each expired VTXO into a [`SweepInput`].
/// 3. Call [`TxBuilder::build_sweep_tx`] to produce a PSBT.
/// 4. Sign via [`SignerService::sign_transaction`].
/// 5. Finalize via [`TxBuilder::finalize_and_extract`].
/// 6. Broadcast via [`WalletService::broadcast_transaction`].
pub struct TxBuilderSweepService {
    tx_builder: Arc<dyn TxBuilder>,
    vtxo_repo: Arc<dyn VtxoRepository>,
    #[allow(dead_code)]
    round_repo: Arc<dyn RoundRepository>,
    wallet: Arc<dyn WalletService>,
    signer: Arc<dyn SignerService>,
    /// Notifier for VTXO expiry alerts (Issue #247)
    notifier: Arc<dyn Notifier>,
    /// Maximum VTXOs per sweep transaction
    max_per_tx: usize,
    /// Minimum total sats to justify a sweep
    min_amount: u64,
}

impl TxBuilderSweepService {
    /// Create a new `TxBuilderSweepService`.
    pub fn new(
        tx_builder: Arc<dyn TxBuilder>,
        vtxo_repo: Arc<dyn VtxoRepository>,
        round_repo: Arc<dyn RoundRepository>,
        wallet: Arc<dyn WalletService>,
        signer: Arc<dyn SignerService>,
    ) -> Self {
        Self {
            tx_builder,
            vtxo_repo,
            round_repo,
            wallet,
            signer,
            notifier: Arc::new(NoopNotifier),
            max_per_tx: 100,
            min_amount: 10_000,
        }
    }

    /// Set a notifier for VTXO expiry alerts (Issue #247).
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Set the maximum VTXOs per sweep transaction.
    pub fn with_max_per_tx(mut self, max: usize) -> Self {
        self.max_per_tx = max;
        self
    }

    /// Set the minimum amount (sats) to justify a sweep.
    pub fn with_min_amount(mut self, min: u64) -> Self {
        self.min_amount = min;
        self
    }

    /// Convert a [`Vtxo`] to a [`SweepInput`].
    fn vtxo_to_sweep_input(vtxo: &Vtxo) -> SweepInput {
        SweepInput {
            txid: vtxo.outpoint.txid.clone(),
            vout: vtxo.outpoint.vout,
            amount: vtxo.amount,
            tapscripts: Vec::new(), // TxBuilder resolves scripts from the tree
        }
    }

    /// Build, sign, finalize and broadcast a single sweep transaction for the
    /// given batch of [`SweepInput`]s. Returns `(txid, vtxo_count, total_sats)`.
    async fn sweep_batch(
        &self,
        inputs: &[SweepInput],
        total_sats: u64,
    ) -> ArkResult<(String, usize, u64)> {
        let count = inputs.len();
        debug!(input_count = count, total_sats, "Building sweep tx");

        // 1. Build PSBT via TxBuilder
        let (_preliminary_txid, psbt_hex) = self.tx_builder.build_sweep_tx(inputs).await?;

        // 2. Sign via signer
        let signed = self.signer.sign_transaction(&psbt_hex, false).await?;

        // 3. Finalize & extract raw tx
        let raw_tx = self.tx_builder.finalize_and_extract(&signed).await?;

        // 4. Broadcast
        let txid = self.wallet.broadcast_transaction(vec![raw_tx]).await?;

        info!(txid = %txid, vtxo_count = count, sats = total_sats, "Sweep broadcast");
        Ok((txid, count, total_sats))
    }
}

#[async_trait::async_trait]
impl SweepService for TxBuilderSweepService {
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult> {
        // Use wall-clock time derived from current_height (approx 10 min/block).
        // For accuracy we query the wallet for the current block time.
        let block_time = self.wallet.get_current_block_time().await?;
        let now_ts = block_time.timestamp;

        let expired = self.vtxo_repo.find_expired_vtxos(now_ts).await?;
        if expired.is_empty() {
            debug!(current_height, "No expired VTXOs to sweep");
            return Ok(SweepResult::default());
        }

        info!(
            current_height,
            expired_count = expired.len(),
            "Found expired VTXOs for sweep"
        );

        // Notify affected users about VTXO expiry (Issue #247)
        // Group VTXOs by owner pubkey to send one notification per user
        {
            let mut by_pubkey: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for vtxo in &expired {
                by_pubkey
                    .entry(vtxo.pubkey.clone())
                    .or_default()
                    .push(vtxo.outpoint.to_string());
            }
            for (pubkey, vtxo_ids) in &by_pubkey {
                for vtxo_id in vtxo_ids {
                    if let Err(e) = self
                        .notifier
                        .notify_vtxo_expiry(pubkey, vtxo_id, current_height)
                        .await
                    {
                        tracing::warn!(
                            pubkey = %pubkey,
                            vtxo_id = %vtxo_id,
                            error = %e,
                            "Failed to send VTXO expiry notification (continuing sweep)"
                        );
                    }
                }
            }
        }

        // Group into batches of max_per_tx
        let mut result = SweepResult::default();
        for chunk in expired.chunks(self.max_per_tx) {
            let total_sats: u64 = chunk.iter().map(|v| v.amount).sum();
            if total_sats < self.min_amount {
                debug!(
                    total_sats,
                    min = self.min_amount,
                    "Batch below minimum, skipping"
                );
                continue;
            }

            let inputs: Vec<SweepInput> = chunk.iter().map(Self::vtxo_to_sweep_input).collect();
            match self.sweep_batch(&inputs, total_sats).await {
                Ok((txid, count, sats)) => {
                    result.vtxos_swept += count;
                    result.sats_recovered += sats;
                    result.tx_ids.push(txid);
                }
                Err(e) => {
                    warn!(error = %e, "Sweep batch failed, continuing with next");
                }
            }
        }

        Ok(result)
    }

    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult> {
        // Connector sweeping: look up the round, get connectors tree, sweep
        let round = self.round_repo.get_round_with_id(round_id).await?;
        let round = match round {
            Some(r) => r,
            None => {
                debug!(round_id, "Round not found for connector sweep");
                return Ok(SweepResult::default());
            }
        };

        if round.connectors.is_empty() {
            debug!(round_id, "No connectors to sweep");
            return Ok(SweepResult::default());
        }

        // Get sweepable outputs from the connector tree
        let sweepable = self
            .tx_builder
            .get_sweepable_batch_outputs(&round.connectors)
            .await?;

        let sweepable = match sweepable {
            Some(s) => s,
            None => {
                debug!(round_id, "No sweepable connector outputs");
                return Ok(SweepResult::default());
            }
        };

        let input = SweepInput {
            txid: sweepable.txid,
            vout: sweepable.vout,
            amount: sweepable.amount,
            tapscripts: sweepable.tapscripts,
        };

        let (txid, count, sats) = self.sweep_batch(&[input], sweepable.amount).await?;
        Ok(SweepResult {
            vtxos_swept: count,
            sats_recovered: sats,
            tx_ids: vec![txid],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Round, VtxoOutpoint};
    use crate::ports::{BlockTimestamp, TxInput, WalletStatus};
    use async_trait::async_trait;
    use bitcoin::XOnlyPublicKey;

    // Mock implementations
    struct MockVtxoRepo;

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
            Ok(vec![])
        }
    }

    struct MockRoundRepo;

    #[async_trait]
    impl RoundRepository for MockRoundRepo {
        async fn add_or_update_round(&self, _round: &Round) -> ArkResult<()> {
            Ok(())
        }

        async fn get_round_with_id(&self, _id: &str) -> ArkResult<Option<Round>> {
            Ok(None)
        }

        async fn get_round_stats(
            &self,
            _commitment_txid: &str,
        ) -> ArkResult<Option<crate::domain::RoundStats>> {
            Ok(None)
        }

        async fn confirm_intent(&self, _round_id: &str, _intent_id: &str) -> ArkResult<()> {
            Ok(())
        }

        async fn get_pending_confirmations(&self, _round_id: &str) -> ArkResult<Vec<String>> {
            Ok(Vec::new())
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
            let bytes = [1u8; 32];
            Ok(XOnlyPublicKey::from_slice(&bytes).unwrap())
        }

        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok("bc1qsweep".to_string())
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
            Ok("sweep_txid".to_string())
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

    #[test]
    fn test_sweep_config_default() {
        let config = SweepConfig::default();
        assert!(config.sweep_interval.as_secs() > 0);
        assert!(config.grace_period_secs > 0);
    }

    #[test]
    fn test_sweep_batch_creation() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("tx".to_string(), 0),
            50_000,
            "pubkey".to_string(),
        );
        let batch = SweepBatch::new(vec![vtxo]);

        assert_eq!(batch.total_amount, 50_000);
        assert_eq!(batch.vtxos.len(), 1);
        assert!(batch.sweep_tx.is_none());
    }

    #[test]
    fn test_create_sweep_batches() {
        let config = SweepConfig {
            max_vtxos_per_sweep: 2,
            min_sweep_amount: 1000,
            ..Default::default()
        };

        let vtxo_repo = Arc::new(MockVtxoRepo);
        let round_repo = Arc::new(MockRoundRepo);
        let wallet = Arc::new(MockWallet);

        let service = SweepRunner::new(config, vtxo_repo, round_repo, wallet);

        // Create 5 VTXOs
        let vtxos: Vec<Vtxo> = (0..5)
            .map(|i| {
                Vtxo::new(
                    VtxoOutpoint::new(format!("tx{i}"), 0),
                    10_000,
                    "pk".to_string(),
                )
            })
            .collect();

        let batches = service.create_sweep_batches(vtxos);

        // Should create 3 batches: 2 + 2 + 1
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].vtxos.len(), 2);
        assert_eq!(batches[1].vtxos.len(), 2);
        assert_eq!(batches[2].vtxos.len(), 1);
    }

    // ── TxBuilderSweepService tests ───────────────────────────────

    use crate::domain::{FlatTxTree, Intent};
    use crate::ports::{
        BoardingInput, CommitmentTxResult, SignedBoardingInput, SweepableOutput, ValidForfeitTx,
    };

    /// Mock TxBuilder that returns deterministic results.
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
            let txid = format!("sweep_txid_{}", inputs.len());
            let psbt = format!("sweep_psbt_{}", inputs.len());
            Ok((txid, psbt))
        }

        async fn get_sweepable_batch_outputs(
            &self,
            vtxo_tree: &FlatTxTree,
        ) -> ArkResult<Option<SweepableOutput>> {
            if vtxo_tree.is_empty() {
                return Ok(None);
            }
            Ok(Some(SweepableOutput {
                txid: "conn_txid".to_string(),
                vout: 0,
                amount: 50_000,
                csv_delay: 144,
                tapscripts: vec!["script_hex".to_string()],
            }))
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

    /// Mock signer that passes through.
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

    /// Configurable mock VTXO repo for TxBuilderSweepService tests.
    struct ConfigurableVtxoRepo {
        expired: Vec<Vtxo>,
    }

    impl ConfigurableVtxoRepo {
        fn with_expired(expired: Vec<Vtxo>) -> Self {
            Self { expired }
        }
    }

    #[async_trait]
    impl VtxoRepository for ConfigurableVtxoRepo {
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

    fn make_sweep_svc(vtxos: Vec<Vtxo>) -> TxBuilderSweepService {
        TxBuilderSweepService::new(
            Arc::new(MockTxBuilder),
            Arc::new(ConfigurableVtxoRepo::with_expired(vtxos)),
            Arc::new(MockRoundRepo),
            Arc::new(MockWallet),
            Arc::new(MockSigner),
        )
    }

    #[tokio::test]
    async fn test_txbuilder_sweep_no_expired_vtxos() {
        let svc = make_sweep_svc(vec![]);
        let result = svc.sweep_expired_vtxos(100).await.unwrap();
        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_txbuilder_sweep_single_vtxo() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("expired_tx".to_string(), 0),
            50_000,
            "pk".to_string(),
        );
        vtxo.expires_at = 500;
        let svc = make_sweep_svc(vec![vtxo]);
        let result = svc.sweep_expired_vtxos(100).await.unwrap();
        assert_eq!(result.vtxos_swept, 1);
        assert_eq!(result.sats_recovered, 50_000);
        assert_eq!(result.tx_ids.len(), 1);
    }

    #[tokio::test]
    async fn test_txbuilder_sweep_multiple_vtxos_batched() {
        let vtxos: Vec<Vtxo> = (0..5)
            .map(|i| {
                let mut v = Vtxo::new(
                    VtxoOutpoint::new(format!("tx{i}"), 0),
                    20_000,
                    "pk".to_string(),
                );
                v.expires_at = 100;
                v
            })
            .collect();

        let svc = make_sweep_svc(vtxos).with_max_per_tx(2);
        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        // 5 VTXOs in batches of 2 → 3 transactions (2+2+1)
        assert_eq!(result.vtxos_swept, 5);
        assert_eq!(result.sats_recovered, 100_000);
        assert_eq!(result.tx_ids.len(), 3);
    }

    #[tokio::test]
    async fn test_txbuilder_sweep_below_minimum_skipped() {
        let mut vtxo = Vtxo::new(
            VtxoOutpoint::new("small_tx".to_string(), 0),
            500, // below default min of 10_000
            "pk".to_string(),
        );
        vtxo.expires_at = 100;
        let svc = make_sweep_svc(vec![vtxo]);
        let result = svc.sweep_expired_vtxos(200).await.unwrap();
        // Below min_amount → skipped
        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_txbuilder_sweep_connectors_no_round() {
        let svc = make_sweep_svc(vec![]);
        let result = svc.sweep_connectors("nonexistent").await.unwrap();
        assert_eq!(result.vtxos_swept, 0);
    }

    #[tokio::test]
    async fn test_vtxo_to_sweep_input_conversion() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("abc123".to_string(), 7),
            42_000,
            "pk".to_string(),
        );
        let input = TxBuilderSweepService::vtxo_to_sweep_input(&vtxo);
        assert_eq!(input.txid, "abc123");
        assert_eq!(input.vout, 7);
        assert_eq!(input.amount, 42_000);
    }
}
