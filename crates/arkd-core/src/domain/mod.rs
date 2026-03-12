//! Domain models for the Ark protocol
//!
//! Terminology aligns with Go arkd:
//! - **Intent** replaces "Participant"
//! - **VtxoOutpoint** replaces "VtxoId"
//! - Stage-based round lifecycle (Registration/Finalization)

pub mod exit;
pub mod intent;
pub mod round;
pub mod vtxo;

pub use exit::{
    BoardingRequest, BoardingStatus, BoardingTransaction, CollaborativeExitRequest, Exit,
    ExitError, ExitStatus, ExitSummary, ExitType, UnilateralExitRequest,
};
pub use intent::Intent;
pub use round::{
    FlatTxTree, ForfeitTx, Round, RoundConfig, RoundStage, RoundStats, Stage, TxTreeNode,
};
pub use vtxo::{Receiver, Vtxo, VtxoId, VtxoOutpoint};

/// Default VTXO expiry in seconds (~7 days)
pub const DEFAULT_VTXO_EXPIRY_SECS: i64 = 7 * 24 * 60 * 60;
/// Default min intents
pub const DEFAULT_MIN_INTENTS: u32 = 1;
/// Default max intents
pub const DEFAULT_MAX_INTENTS: u32 = 128;
/// Default unilateral exit delay (blocks)
pub const DEFAULT_UNILATERAL_EXIT_DELAY: u32 = 512;
/// Min VTXO amount (dust limit)
pub const MIN_VTXO_AMOUNT_SATS: u64 = 546;
/// Default session duration (seconds)
pub const DEFAULT_SESSION_DURATION_SECS: u64 = 10;

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
