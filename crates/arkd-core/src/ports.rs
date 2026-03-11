//! Ports - External interfaces for dependency inversion
//!
//! Following hexagonal architecture (ports & adapters pattern), these traits
//! define the contracts that external adapters must implement. This allows
//! the core domain logic to remain independent of infrastructure concerns.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                         Application Core                            │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
//! │  │     Domain      │  │   Application   │  │     Ports       │     │
//! │  │     Models      │  │    Services     │  │   (Interfaces)  │     │
//! │  └─────────────────┘  └─────────────────┘  └────────┬────────┘     │
//! └────────────────────────────────────────────────────┬────────────────┘
//!                                                      │
//!          ┌───────────────────┬───────────────────────┼───────────────────┐
//!          │                   │                       │                   │
//!          ▼                   ▼                       ▼                   ▼
//!   ┌─────────────┐   ┌─────────────┐         ┌─────────────┐   ┌─────────────┐
//!   │   Wallet    │   │  Database   │         │   Bitcoin   │   │    Cache    │
//!   │   Adapter   │   │   Adapter   │         │ RPC Adapter │   │   Adapter   │
//!   └─────────────┘   └─────────────┘         └─────────────┘   └─────────────┘
//! ```
//!
//! # Port Types
//!
//! - **WalletService**: Bitcoin wallet operations (signing, UTXOs)
//! - **DatabaseService**: Persistent storage for rounds, VTXOs, etc.
//! - **BitcoinRpcService**: Bitcoin node communication
//! - **CacheService**: Fast in-memory caching (Redis)

use async_trait::async_trait;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid, XOnlyPublicKey};
use uuid::Uuid;

use crate::domain::{Exit, ExitStatus, Participant, Round, RoundStatus, Vtxo, VtxoId, VtxoStatus};
use crate::error::ArkResult;

// =============================================================================
// Wallet Service
// =============================================================================

/// Wallet service interface for Bitcoin wallet operations
///
/// Handles key management, transaction signing, and UTXO tracking
/// for the Ark Service Provider's liquidity.
#[async_trait]
pub trait WalletService: Send + Sync {
    /// Get the current wallet balance
    async fn get_balance(&self) -> ArkResult<Amount>;

    /// Get available (confirmed) balance
    async fn get_available_balance(&self, min_confirmations: u32) -> ArkResult<Amount>;

    /// Generate a new receiving address
    async fn get_new_address(&self) -> ArkResult<Address>;

    /// Get list of available UTXOs
    async fn get_utxos(&self, min_confirmations: u32) -> ArkResult<Vec<WalletUtxo>>;

    /// Sign a PSBT (Partially Signed Bitcoin Transaction)
    async fn sign_psbt(&self, psbt: &mut bitcoin::psbt::Psbt) -> ArkResult<()>;

    /// Sign a message with the wallet's key
    async fn sign_message(&self, message: &[u8]) -> ArkResult<Vec<u8>>;

    /// Broadcast a transaction
    async fn broadcast_transaction(&self, tx: &Transaction) -> ArkResult<Txid>;

    /// Get the ASP's public key (for VTXO scripts)
    async fn get_asp_pubkey(&self) -> ArkResult<XOnlyPublicKey>;
}

/// A UTXO owned by the wallet
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    /// The outpoint
    pub outpoint: OutPoint,
    /// Amount in satoshis
    pub amount: Amount,
    /// Number of confirmations
    pub confirmations: u32,
    /// Whether this UTXO is already reserved for use
    pub reserved: bool,
}

// =============================================================================
// Database Service
// =============================================================================

/// Database service interface for persistent storage
///
/// Provides CRUD operations for all domain entities:
/// rounds, VTXOs, participants, and exits.
#[async_trait]
pub trait DatabaseService: Send + Sync {
    // =========================================================================
    // Round Operations
    // =========================================================================

    /// Save a round
    async fn save_round(&self, round: &Round) -> ArkResult<()>;

    /// Get a round by ID
    async fn get_round(&self, id: Uuid) -> ArkResult<Option<Round>>;

    /// Get the current active round (if any)
    async fn get_active_round(&self) -> ArkResult<Option<Round>>;

    /// List rounds by status
    async fn list_rounds(&self, status: Option<RoundStatus>, limit: u32) -> ArkResult<Vec<Round>>;

    /// Update round status
    async fn update_round_status(&self, id: Uuid, status: RoundStatus) -> ArkResult<()>;

    // =========================================================================
    // VTXO Operations
    // =========================================================================

    /// Save a VTXO
    async fn save_vtxo(&self, vtxo: &Vtxo) -> ArkResult<()>;

    /// Save multiple VTXOs (batch)
    async fn save_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()>;

    /// Get a VTXO by ID
    async fn get_vtxo(&self, id: &VtxoId) -> ArkResult<Option<Vtxo>>;

    /// Get VTXOs by owner public key
    async fn get_vtxos_by_owner(&self, pubkey: &XOnlyPublicKey) -> ArkResult<Vec<Vtxo>>;

    /// Get VTXOs by status
    async fn get_vtxos_by_status(&self, status: VtxoStatus) -> ArkResult<Vec<Vtxo>>;

    /// Get VTXOs expiring before a given height
    async fn get_vtxos_expiring_before(&self, height: u32) -> ArkResult<Vec<Vtxo>>;

    /// Update VTXO status
    async fn update_vtxo_status(&self, id: &VtxoId, status: VtxoStatus) -> ArkResult<()>;

    // =========================================================================
    // Participant Operations
    // =========================================================================

    /// Save a participant for a round
    async fn save_participant(&self, round_id: Uuid, participant: &Participant) -> ArkResult<()>;

    /// Get participants for a round
    async fn get_participants(&self, round_id: Uuid) -> ArkResult<Vec<Participant>>;

    /// Check if a pubkey is banned
    async fn is_banned(&self, pubkey: &XOnlyPublicKey) -> ArkResult<bool>;

    /// Ban a participant
    async fn ban_participant(
        &self,
        pubkey: &XOnlyPublicKey,
        reason: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> ArkResult<()>;

    // =========================================================================
    // Exit Operations
    // =========================================================================

    /// Save an exit
    async fn save_exit(&self, exit: &Exit) -> ArkResult<()>;

    /// Get an exit by ID
    async fn get_exit(&self, id: Uuid) -> ArkResult<Option<Exit>>;

    /// Get exits by status
    async fn get_exits_by_status(&self, status: ExitStatus) -> ArkResult<Vec<Exit>>;

    /// Get pending exits for a given VTXO
    async fn get_exits_for_vtxo(&self, vtxo_id: &VtxoId) -> ArkResult<Vec<Exit>>;

    /// Update exit status
    async fn update_exit_status(&self, id: Uuid, status: ExitStatus) -> ArkResult<()>;

    // =========================================================================
    // Transaction Support
    // =========================================================================

    /// Begin a database transaction
    async fn begin_transaction(&self) -> ArkResult<Box<dyn DatabaseTransaction>>;
}

/// Database transaction interface
///
/// Allows multiple operations to be executed atomically.
#[async_trait]
pub trait DatabaseTransaction: Send + Sync {
    /// Commit the transaction
    async fn commit(self: Box<Self>) -> ArkResult<()>;

    /// Rollback the transaction
    async fn rollback(self: Box<Self>) -> ArkResult<()>;
}

// =============================================================================
// Bitcoin RPC Service
// =============================================================================

/// Bitcoin RPC service interface for blockchain interaction
///
/// Provides access to Bitcoin node functionality:
/// block info, transaction broadcasting, and chain queries.
#[async_trait]
pub trait BitcoinRpcService: Send + Sync {
    /// Get current block height
    async fn get_block_height(&self) -> ArkResult<u32>;

    /// Get block hash at height
    async fn get_block_hash(&self, height: u32) -> ArkResult<bitcoin::BlockHash>;

    /// Get a transaction by ID
    async fn get_transaction(&self, txid: &Txid) -> ArkResult<Option<Transaction>>;

    /// Get transaction confirmations
    async fn get_tx_confirmations(&self, txid: &Txid) -> ArkResult<u32>;

    /// Broadcast a transaction
    async fn broadcast_transaction(&self, tx: &Transaction) -> ArkResult<Txid>;

    /// Estimate fee rate for target confirmation blocks
    async fn estimate_fee_rate(&self, target_blocks: u16) -> ArkResult<Amount>;

    /// Check if a transaction is confirmed
    async fn is_tx_confirmed(&self, txid: &Txid, min_confirmations: u32) -> ArkResult<bool>;

    /// Subscribe to new blocks (returns block height)
    async fn subscribe_blocks(&self) -> ArkResult<tokio::sync::broadcast::Receiver<u32>>;
}

// =============================================================================
// Cache Service
// =============================================================================

/// Cache service interface for fast in-memory storage
///
/// Used for temporary state that needs fast access:
/// active round state, participant sessions, etc.
#[async_trait]
pub trait CacheService: Send + Sync {
    /// Set a value with optional TTL (time-to-live)
    async fn set(&self, key: &str, value: &[u8], ttl_seconds: Option<u64>) -> ArkResult<()>;

    /// Get a value
    async fn get(&self, key: &str) -> ArkResult<Option<Vec<u8>>>;

    /// Delete a value
    async fn delete(&self, key: &str) -> ArkResult<bool>;

    /// Check if a key exists
    async fn exists(&self, key: &str) -> ArkResult<bool>;

    /// Set a value if it doesn't exist (for locking)
    async fn set_nx(&self, key: &str, value: &[u8], ttl_seconds: u64) -> ArkResult<bool>;

    /// Increment a counter
    async fn incr(&self, key: &str) -> ArkResult<i64>;

    /// Add to a set
    async fn sadd(&self, key: &str, member: &[u8]) -> ArkResult<bool>;

    /// Remove from a set
    async fn srem(&self, key: &str, member: &[u8]) -> ArkResult<bool>;

    /// Get all members of a set
    async fn smembers(&self, key: &str) -> ArkResult<Vec<Vec<u8>>>;

    /// Publish a message to a channel
    async fn publish(&self, channel: &str, message: &[u8]) -> ArkResult<()>;

    /// Subscribe to a channel
    async fn subscribe(
        &self,
        channel: &str,
    ) -> ArkResult<tokio::sync::broadcast::Receiver<Vec<u8>>>;
}

// =============================================================================
// Event Publisher
// =============================================================================

/// Event types that can be published
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum ArkEvent {
    /// A new round has started
    RoundStarted { round_id: Uuid },

    /// A round has been finalized
    RoundFinalized {
        round_id: Uuid,
        commitment_txid: Txid,
    },

    /// A round has failed
    RoundFailed { round_id: Uuid, reason: String },

    /// A new VTXO has been created
    VtxoCreated {
        vtxo_id: VtxoId,
        owner: XOnlyPublicKey,
    },

    /// A VTXO has been spent
    VtxoSpent { vtxo_id: VtxoId },

    /// An exit has been completed
    ExitCompleted { exit_id: Uuid },

    /// New block received
    NewBlock { height: u32 },
}

/// Event publisher interface
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish an event
    async fn publish(&self, event: ArkEvent) -> ArkResult<()>;

    /// Subscribe to events
    async fn subscribe(&self) -> ArkResult<tokio::sync::broadcast::Receiver<ArkEvent>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verify traits are object-safe
    fn _assert_object_safe<T: ?Sized>() {}

    #[test]
    fn test_traits_are_object_safe() {
        _assert_object_safe::<dyn WalletService>();
        _assert_object_safe::<dyn DatabaseService>();
        _assert_object_safe::<dyn BitcoinRpcService>();
        _assert_object_safe::<dyn CacheService>();
        _assert_object_safe::<dyn EventPublisher>();
    }
}
