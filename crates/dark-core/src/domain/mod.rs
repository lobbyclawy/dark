//! Domain models for the Ark protocol
//!
//! Terminology aligns with Go dark:
//! - **Intent** replaces "Participant"
//! - **VtxoOutpoint** replaces "VtxoId"
//! - Stage-based round lifecycle (Registration/Finalization)

pub mod asset;
pub mod ban;
pub mod checkpoint;
pub mod config_service;
pub mod conviction;
pub mod events;
pub mod exit;
pub mod fee;
pub mod forfeit;
pub mod indexer;
pub mod intent;
pub mod offchain_tx;
pub mod round;
pub mod scheduled_session;
pub mod signing;
pub mod vtxo;

pub use scheduled_session::ScheduledSessionConfig;

pub use asset::{Asset, AssetAmount, AssetId, AssetIssuance, AssetKind, AssetRecord};
pub use ban::{BanReason, BanRecord, InMemoryBanRepository};
pub use checkpoint::{CheckpointTx, DEFAULT_CHECKPOINT_EXIT_DELAY};
pub use conviction::{Conviction, ConvictionKind, CrimeType};
pub use events::ArkEvent;
pub use forfeit::ForfeitRecord;

pub use exit::{
    BoardingRequest, BoardingStatus, BoardingTransaction, CollaborativeExitRequest, Exit,
    ExitError, ExitStatus, ExitSummary, ExitType, UnilateralExitRequest,
};
pub use fee::FeeProgram;
pub use intent::Intent;
pub use offchain_tx::{OffchainTx, OffchainTxError, OffchainTxStage, VtxoInput, VtxoOutput};
pub use round::{
    ConfirmationStatus, FlatTxTree, ForfeitTx, Round, RoundConfig, RoundError, RoundStage,
    RoundStats, Stage, TxTreeNode,
};
pub use signing::{SigningSession, SigningSessionStatus};
pub use vtxo::{Receiver, Vtxo, VtxoId, VtxoOutpoint};

/// Default VTXO expiry in seconds (~7 days)
pub const DEFAULT_VTXO_EXPIRY_SECS: i64 = 7 * 24 * 60 * 60;
/// Default min intents
pub const DEFAULT_MIN_INTENTS: u32 = 1;
/// Default max intents
pub const DEFAULT_MAX_INTENTS: u32 = 128;
/// Average seconds per Bitcoin block (~10 minutes).
/// Used to convert between seconds and block counts.
pub const SECS_PER_BLOCK: u32 = 600;
/// Default unilateral exit delay (seconds, ~24 hours)
// BIP68 time-based locktimes must be multiples of 512 seconds (granularity).
// Use 512s (~8.5 min) as default to match the Go arkd test environment
// (envs/arkd.dev.env: ARKD_UNILATERAL_EXIT_DELAY=512).
// Production deployments should set this to a larger multiple of 512 (e.g. 86016 = 168×512 ≈ 24h).
pub const DEFAULT_UNILATERAL_EXIT_DELAY: u32 = 512;
/// Min VTXO amount (dust limit)
pub const MIN_VTXO_AMOUNT_SATS: u64 = 546;
/// Default session duration (seconds)
pub const DEFAULT_SESSION_DURATION_SECS: u64 = 10;
/// Default min UTXO amount for boarding (sats)
pub const DEFAULT_UTXO_MIN_AMOUNT: u64 = 1_000;
/// Default max UTXO amount for boarding (sats)
pub const DEFAULT_UTXO_MAX_AMOUNT: u64 = 100_000_000;
/// Default CSV delay for public unilateral exits (seconds, ~24 hours)
pub const DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY: u32 = 512;
/// Default CSV delay for boarding inputs (seconds, ~3 months)
// Match Go arkd test env (envs/arkd.dev.env: ARKD_BOARDING_EXIT_DELAY=1024).
pub const DEFAULT_BOARDING_EXIT_DELAY: u32 = 1_024;
/// Default max commitment tx weight
pub const DEFAULT_MAX_TX_WEIGHT: u64 = 400_000;
/// Default event channel capacity for broadcast subscribers
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const { assert!(DEFAULT_VTXO_EXPIRY_SECS > 0) };
        const { assert!(DEFAULT_MAX_INTENTS > DEFAULT_MIN_INTENTS) };
        const { assert!(MIN_VTXO_AMOUNT_SATS >= 546) };
    }
}
