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
use crate::ports::{RoundRepository, VtxoRepository, WalletService};

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
pub struct SweepService {
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

impl SweepService {
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

        let service = SweepService::new(config, vtxo_repo, round_repo, wallet);

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
}
