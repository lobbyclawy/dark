//! Ports - External interfaces for dependency inversion
//!
//! Aligns with Go arkd port interfaces.

use async_trait::async_trait;
use bitcoin::XOnlyPublicKey;

use crate::domain::{FlatTxTree, Intent, Round, Vtxo, VtxoOutpoint};
use crate::error::ArkResult;

/// Wallet service interface
#[async_trait]
pub trait WalletService: Send + Sync {
    /// Check wallet status
    async fn status(&self) -> ArkResult<WalletStatus>;
    /// Get the forfeit pubkey
    async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey>;
    /// Derive a connector address
    async fn derive_connector_address(&self) -> ArkResult<String>;
    /// Sign a PSBT transaction
    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String>;
    /// Select UTXOs for a given amount
    async fn select_utxos(
        &self,
        amount: u64,
        confirmed_only: bool,
    ) -> ArkResult<(Vec<TxInput>, u64)>;
    /// Broadcast a transaction
    async fn broadcast_transaction(&self, txs: Vec<String>) -> ArkResult<String>;
    /// Get current fee rate (sat/vB)
    async fn fee_rate(&self) -> ArkResult<u64>;
    /// Get the current block timestamp
    async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp>;
    /// Get dust amount
    async fn get_dust_amount(&self) -> ArkResult<u64>;
    /// Get outpoint status
    async fn get_outpoint_status(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool>;
}

/// Wallet status
#[derive(Debug, Clone)]
pub struct WalletStatus {
    /// Initialized
    pub initialized: bool,
    /// Unlocked
    pub unlocked: bool,
    /// Synced
    pub synced: bool,
}

/// Transaction input
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount
    pub amount: u64,
    /// Script
    pub script: String,
}

/// Block timestamp
#[derive(Debug, Clone)]
pub struct BlockTimestamp {
    /// Height
    pub height: u64,
    /// Timestamp
    pub timestamp: i64,
}

/// Signer service
#[async_trait]
pub trait SignerService: Send + Sync {
    /// Get pubkey
    async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey>;
    /// Sign PSBT
    async fn sign_transaction(&self, partial_tx: &str, extract_raw: bool) -> ArkResult<String>;
}

/// Transaction builder
#[async_trait]
pub trait TxBuilder: Send + Sync {
    /// Build commitment tx
    async fn build_commitment_tx(
        &self,
        signer_pubkey: &XOnlyPublicKey,
        intents: &[Intent],
        boarding_inputs: &[BoardingInput],
    ) -> ArkResult<CommitmentTxResult>;

    /// Verify forfeit txs
    async fn verify_forfeit_txs(
        &self,
        vtxos: &[Vtxo],
        connectors: &FlatTxTree,
        txs: &[String],
    ) -> ArkResult<Vec<ValidForfeitTx>>;
}

/// Commitment tx result
#[derive(Debug, Clone)]
pub struct CommitmentTxResult {
    /// Commitment tx (PSBT)
    pub commitment_tx: String,
    /// VTXO tree
    pub vtxo_tree: FlatTxTree,
    /// Connector address
    pub connector_address: String,
    /// Connectors
    pub connectors: FlatTxTree,
}

/// Boarding input
#[derive(Debug, Clone)]
pub struct BoardingInput {
    /// Outpoint
    pub outpoint: VtxoOutpoint,
    /// Amount
    pub amount: u64,
}

/// Validated forfeit tx
#[derive(Debug, Clone)]
pub struct ValidForfeitTx {
    /// Tx
    pub tx: String,
    /// Connector
    pub connector: VtxoOutpoint,
}

/// VTXO repository
#[async_trait]
pub trait VtxoRepository: Send + Sync {
    /// Add VTXOs
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()>;
    /// Get VTXOs
    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>>;
    /// Get all for pubkey
    async fn get_all_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)>;
    /// Spend VTXOs
    async fn spend_vtxos(&self, spent: &[(VtxoOutpoint, String)], ark_txid: &str) -> ArkResult<()>;
    /// Find expired VTXOs eligible for sweep
    ///
    /// Returns VTXOs where expires_at < before_timestamp and not spent/swept/unrolled.
    async fn find_expired_vtxos(&self, before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
        // Default implementation returns empty — override in concrete repos
        let _ = before_timestamp;
        Ok(Vec::new())
    }
}

/// Round repository
#[async_trait]
pub trait RoundRepository: Send + Sync {
    /// Save/update round
    async fn add_or_update_round(&self, round: &Round) -> ArkResult<()>;
    /// Get by ID
    async fn get_round_with_id(&self, id: &str) -> ArkResult<Option<Round>>;
    /// Get stats
    async fn get_round_stats(
        &self,
        commitment_txid: &str,
    ) -> ArkResult<Option<crate::domain::RoundStats>>;
    /// Confirm a specific intent within a round
    async fn confirm_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()>;
    /// Get intent IDs that have not yet confirmed in a round
    async fn get_pending_confirmations(&self, round_id: &str) -> ArkResult<Vec<String>>;
}

/// Cache service
#[async_trait]
pub trait CacheService: Send + Sync {
    /// Set value
    async fn set(&self, key: &str, value: &[u8], ttl_seconds: Option<u64>) -> ArkResult<()>;
    /// Get value
    async fn get(&self, key: &str) -> ArkResult<Option<Vec<u8>>>;
    /// Delete value
    async fn delete(&self, key: &str) -> ArkResult<bool>;
}

/// Event types
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ArkEvent {
    /// Round started
    RoundStarted { round_id: String, timestamp: i64 },
    /// Round finalized
    RoundFinalized {
        round_id: String,
        commitment_tx: String,
        timestamp: i64,
    },
    /// Round failed
    RoundFailed {
        round_id: String,
        reason: String,
        timestamp: i64,
    },
}

/// Event publisher
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish event
    async fn publish_event(&self, event: ArkEvent) -> ArkResult<()>;
    /// Subscribe
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn _assert_object_safe<T: ?Sized>() {}

    #[test]
    fn test_traits_are_object_safe() {
        _assert_object_safe::<dyn WalletService>();
        _assert_object_safe::<dyn SignerService>();
        _assert_object_safe::<dyn VtxoRepository>();
        _assert_object_safe::<dyn RoundRepository>();
        _assert_object_safe::<dyn CacheService>();
    }
}
