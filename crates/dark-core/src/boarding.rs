//! Boarding Service — on-chain funds to VTXOs
//!
//! Boarding allows users to add on-chain Bitcoin into the Ark protocol
//! by creating tapscript-based boarding inputs that get included in
//! a commitment transaction during round finalization.
//!
//! Flow:
//! 1. User requests boarding with amount and recipient pubkey
//! 2. ASP creates a boarding address (tapscript with user + ASP keys)
//! 3. User sends on-chain funds to boarding address
//! 4. ASP detects funding and marks boarding as funded
//! 5. During next round, ASP includes boarding input in commitment tx
//! 6. User receives VTXO in the round's VTXO tree

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::domain::exit::{BoardingRequest, BoardingStatus, BoardingTransaction};
use crate::error::{ArkError, ArkResult};
use crate::ports::{BoardingInput, VtxoRepository, WalletService};

/// Boarding service configuration
#[derive(Debug, Clone)]
pub struct BoardingConfig {
    /// Minimum boarding amount (sats)
    pub min_amount: u64,
    /// Maximum boarding amount (sats)
    pub max_amount: u64,
    /// Boarding expiry timeout (seconds) — how long before unfunded boardings expire
    pub expiry_timeout_secs: i64,
    /// Confirmations required for boarding funding tx
    pub required_confirmations: u32,
}

impl Default for BoardingConfig {
    fn default() -> Self {
        Self {
            min_amount: 10_000,                // 10k sats minimum
            max_amount: 2_100_000_000_000_000, // 21M BTC
            expiry_timeout_secs: 3600,         // 1 hour
            required_confirmations: 1,
        }
    }
}

/// Manages boarding operations
pub struct BoardingService {
    config: BoardingConfig,
    #[allow(dead_code)] // Used in future boarding address derivation
    wallet: Arc<dyn WalletService>,
    #[allow(dead_code)]
    vtxo_repo: Arc<dyn VtxoRepository>,
    /// Active boarding transactions indexed by ID
    /// TODO(#9): Back with SQLite persistence to survive restarts
    active_boardings: Arc<RwLock<HashMap<String, BoardingTransaction>>>,
}

impl BoardingService {
    /// Create a new boarding service
    pub fn new(
        config: BoardingConfig,
        wallet: Arc<dyn WalletService>,
        vtxo_repo: Arc<dyn VtxoRepository>,
    ) -> Self {
        Self {
            config,
            wallet,
            vtxo_repo,
            active_boardings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Request a new boarding
    ///
    /// Creates a boarding transaction and returns the boarding address
    /// where the user should send funds.
    #[instrument(skip(self, request))]
    pub async fn request_boarding(
        &self,
        request: BoardingRequest,
    ) -> ArkResult<BoardingTransaction> {
        // Validate amount
        self.validate_boarding_amount(request.amount)?;

        // Create the boarding transaction record
        let boarding = BoardingTransaction::new(request.recipient_pubkey, request.amount);

        info!(
            boarding_id = %boarding.id,
            amount = %request.amount,
            "Boarding requested"
        );

        // Store it
        self.active_boardings
            .write()
            .await
            .insert(boarding.id.to_string(), boarding.clone());

        Ok(boarding)
    }

    /// Mark a boarding as funded (on-chain tx detected)
    #[instrument(skip(self))]
    pub async fn mark_funded(
        &self,
        boarding_id: &str,
        funding_txid: bitcoin::Txid,
        funding_vout: u32,
    ) -> ArkResult<()> {
        let mut boardings = self.active_boardings.write().await;
        let boarding = boardings
            .get_mut(boarding_id)
            .ok_or_else(|| ArkError::Internal(format!("Boarding not found: {boarding_id}")))?;

        if boarding.status != BoardingStatus::AwaitingFunding {
            return Err(ArkError::Internal(format!(
                "Boarding {} is not awaiting funding (status: {:?})",
                boarding_id, boarding.status
            )));
        }

        boarding.status = BoardingStatus::Funded;
        boarding.funding_txid = Some(funding_txid);
        boarding.funding_vout = Some(funding_vout);
        boarding.updated_at = chrono::Utc::now();

        info!(boarding_id, %funding_txid, "Boarding funded");
        Ok(())
    }

    /// Get funded boardings ready for inclusion in a round
    pub async fn get_funded_boardings(&self) -> Vec<BoardingTransaction> {
        self.active_boardings
            .read()
            .await
            .values()
            .filter(|b| b.status == BoardingStatus::Funded)
            .cloned()
            .collect()
    }

    /// Convert funded boardings to boarding inputs for commitment tx building
    pub async fn get_boarding_inputs(&self) -> Vec<BoardingInput> {
        self.get_funded_boardings()
            .await
            .into_iter()
            .filter_map(|b| {
                let txid = b.funding_txid?;
                let vout = b.funding_vout?;
                Some(BoardingInput {
                    outpoint: crate::domain::VtxoOutpoint::new(txid.to_string(), vout),
                    amount: b.amount.to_sat(),
                })
            })
            .collect()
    }

    /// Mark boardings as included in a round
    #[instrument(skip(self, boarding_ids))]
    pub async fn mark_in_round(
        &self,
        boarding_ids: &[String],
        round_id: uuid::Uuid,
    ) -> ArkResult<()> {
        let mut boardings = self.active_boardings.write().await;
        for id in boarding_ids {
            if let Some(boarding) = boardings.get_mut(id) {
                boarding.status = BoardingStatus::InRound;
                boarding.round_id = Some(round_id);
                boarding.updated_at = chrono::Utc::now();
                debug!(boarding_id = %id, %round_id, "Boarding included in round");
            }
        }
        Ok(())
    }

    /// Complete boardings after round finalization
    #[instrument(skip(self, boarding_ids))]
    pub async fn complete_boardings(
        &self,
        boarding_ids: &[String],
        vtxo_ids: &[crate::domain::VtxoId],
    ) -> ArkResult<()> {
        let mut boardings = self.active_boardings.write().await;
        for (id, vtxo_id) in boarding_ids.iter().zip(vtxo_ids.iter()) {
            if let Some(boarding) = boardings.get_mut(id) {
                boarding.status = BoardingStatus::Completed;
                boarding.vtxo_id = Some(vtxo_id.clone());
                boarding.updated_at = chrono::Utc::now();
                info!(boarding_id = %id, "Boarding completed");
            }
        }
        Ok(())
    }

    /// Expire stale boardings that were never funded
    #[instrument(skip(self))]
    pub async fn expire_stale_boardings(&self) -> ArkResult<usize> {
        let now = chrono::Utc::now();
        let mut boardings = self.active_boardings.write().await;
        let mut expired_count = 0;

        for boarding in boardings.values_mut() {
            if boarding.status == BoardingStatus::AwaitingFunding {
                let age = now.signed_duration_since(boarding.created_at).num_seconds();
                if age >= self.config.expiry_timeout_secs {
                    boarding.status = BoardingStatus::Expired;
                    boarding.updated_at = now;
                    expired_count += 1;
                }
            }
        }

        if expired_count > 0 {
            warn!(count = expired_count, "Expired stale boardings");
        }

        // Remove completed/expired boardings older than 24h
        let retention_threshold = now.timestamp() - 86400;
        boardings.retain(|_, b| {
            !matches!(
                b.status,
                BoardingStatus::Completed | BoardingStatus::Expired | BoardingStatus::Failed
            ) || b.updated_at.timestamp() > retention_threshold
        });

        Ok(expired_count)
    }

    /// Get a boarding by ID
    pub async fn get_boarding(&self, id: &str) -> Option<BoardingTransaction> {
        self.active_boardings.read().await.get(id).cloned()
    }

    /// Get all active boardings
    pub async fn get_active_boardings(&self) -> Vec<BoardingTransaction> {
        self.active_boardings
            .read()
            .await
            .values()
            .filter(|b| !b.status.is_terminal())
            .cloned()
            .collect()
    }

    /// Validate boarding amount
    fn validate_boarding_amount(&self, amount: bitcoin::Amount) -> ArkResult<()> {
        let sats = amount.to_sat();
        if sats < self.config.min_amount {
            return Err(ArkError::AmountTooSmall {
                amount: sats,
                minimum: self.config.min_amount,
            });
        }
        if sats > self.config.max_amount {
            return Err(ArkError::InvalidExitRequest(format!(
                "Boarding amount {} exceeds maximum {}",
                sats, self.config.max_amount
            )));
        }

        Ok(())
    }

    /// Get boarding statistics
    pub async fn stats(&self) -> BoardingStats {
        let boardings = self.active_boardings.read().await;
        let mut stats = BoardingStats::default();

        for b in boardings.values() {
            match b.status {
                BoardingStatus::AwaitingFunding => stats.awaiting_funding += 1,
                BoardingStatus::Funded => {
                    stats.funded += 1;
                    stats.funded_amount += b.amount.to_sat();
                }
                BoardingStatus::InRound => stats.in_round += 1,
                BoardingStatus::Completed => {
                    stats.completed += 1;
                    stats.total_boarded += b.amount.to_sat();
                }
                BoardingStatus::Failed => stats.failed += 1,
                BoardingStatus::Expired => stats.expired += 1,
            }
        }

        stats
    }
}

/// Statistics about boarding operations
#[derive(Debug, Clone, Default)]
pub struct BoardingStats {
    /// Boardings awaiting funding
    pub awaiting_funding: u64,
    /// Funded boardings ready for round
    pub funded: u64,
    /// Total funded amount (sats)
    pub funded_amount: u64,
    /// Boardings currently in a round
    pub in_round: u64,
    /// Completed boardings
    pub completed: u64,
    /// Total amount boarded (sats)
    pub total_boarded: u64,
    /// Failed boardings
    pub failed: u64,
    /// Expired boardings
    pub expired: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VtxoOutpoint;
    use crate::ports::{BlockTimestamp, TxInput, WalletStatus};
    use async_trait::async_trait;
    use bitcoin::{Amount, XOnlyPublicKey};

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
            Ok("bc1qtest".to_string())
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
            Ok("txid".to_string())
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

    struct MockVtxoRepo;

    #[async_trait]
    impl VtxoRepository for MockVtxoRepo {
        async fn add_vtxos(&self, _vtxos: &[crate::domain::Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(
            &self,
            _outpoints: &[VtxoOutpoint],
        ) -> ArkResult<Vec<crate::domain::Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(
            &self,
            _pubkey: &str,
        ) -> ArkResult<(Vec<crate::domain::Vtxo>, Vec<crate::domain::Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(
            &self,
            _spent: &[(VtxoOutpoint, String)],
            _ark_txid: &str,
        ) -> ArkResult<()> {
            Ok(())
        }
    }

    fn test_xonly_pubkey() -> XOnlyPublicKey {
        let bytes = [2u8; 32];
        XOnlyPublicKey::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_boarding_request() {
        let service = BoardingService::new(
            BoardingConfig::default(),
            Arc::new(MockWallet),
            Arc::new(MockVtxoRepo),
        );

        let request = BoardingRequest {
            recipient_pubkey: test_xonly_pubkey(),
            amount: Amount::from_sat(50_000),
        };

        let boarding = service.request_boarding(request).await.unwrap();
        assert_eq!(boarding.status, BoardingStatus::AwaitingFunding);
        assert_eq!(boarding.amount, Amount::from_sat(50_000));
    }

    #[tokio::test]
    async fn test_boarding_amount_too_small() {
        let service = BoardingService::new(
            BoardingConfig::default(),
            Arc::new(MockWallet),
            Arc::new(MockVtxoRepo),
        );

        let request = BoardingRequest {
            recipient_pubkey: test_xonly_pubkey(),
            amount: Amount::from_sat(100), // Below minimum
        };

        assert!(service.request_boarding(request).await.is_err());
    }

    #[tokio::test]
    async fn test_boarding_lifecycle() {
        let service = BoardingService::new(
            BoardingConfig::default(),
            Arc::new(MockWallet),
            Arc::new(MockVtxoRepo),
        );

        // Request boarding
        let request = BoardingRequest {
            recipient_pubkey: test_xonly_pubkey(),
            amount: Amount::from_sat(50_000),
        };
        let boarding = service.request_boarding(request).await.unwrap();
        let id = boarding.id.to_string();

        // Mark as funded
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::all_zeros();
        service.mark_funded(&id, txid, 0).await.unwrap();

        // Check funded boardings
        let funded = service.get_funded_boardings().await;
        assert_eq!(funded.len(), 1);
        assert_eq!(funded[0].status, BoardingStatus::Funded);

        // Get boarding inputs
        let inputs = service.get_boarding_inputs().await;
        assert_eq!(inputs.len(), 1);

        // Mark in round
        let round_id = uuid::Uuid::new_v4();
        service
            .mark_in_round(std::slice::from_ref(&id), round_id)
            .await
            .unwrap();

        let boarding = service.get_boarding(&id).await.unwrap();
        assert_eq!(boarding.status, BoardingStatus::InRound);
        assert_eq!(boarding.round_id, Some(round_id));
    }

    #[tokio::test]
    async fn test_boarding_stats() {
        let service = BoardingService::new(
            BoardingConfig::default(),
            Arc::new(MockWallet),
            Arc::new(MockVtxoRepo),
        );

        // Create two boardings
        for _ in 0..2 {
            let request = BoardingRequest {
                recipient_pubkey: test_xonly_pubkey(),
                amount: Amount::from_sat(50_000),
            };
            service.request_boarding(request).await.unwrap();
        }

        let stats = service.stats().await;
        assert_eq!(stats.awaiting_funding, 2);
    }

    #[tokio::test]
    async fn test_expire_stale_boardings() {
        let config = BoardingConfig {
            expiry_timeout_secs: 0, // Expire immediately for testing
            ..Default::default()
        };

        let service = BoardingService::new(config, Arc::new(MockWallet), Arc::new(MockVtxoRepo));

        let request = BoardingRequest {
            recipient_pubkey: test_xonly_pubkey(),
            amount: Amount::from_sat(50_000),
        };
        service.request_boarding(request).await.unwrap();

        // Small delay to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let expired = service.expire_stale_boardings().await.unwrap();
        assert_eq!(expired, 1);
    }
}
