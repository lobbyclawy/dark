//! Domain models for the Ark protocol
//!
//! This module contains the core business entities and value objects
//! that represent the Ark protocol concepts.
//!
//! # Overview
//!
//! The Ark protocol enables Bitcoin Layer 2 scaling through batched transactions:
//!
//! - **VTXOs** (Virtual Transaction Outputs): Off-chain Bitcoin outputs
//! - **Rounds**: Batching mechanism for VTXO creation
//! - **Participants**: Users participating in rounds
//! - **Exits**: Mechanisms to withdraw VTXOs to on-chain Bitcoin
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Domain Layer                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────┐  ┌─────────┐  ┌─────────────┐  ┌─────────┐    │
//! │  │  VTXO   │  │  Round  │  │ Participant │  │  Exit   │    │
//! │  └─────────┘  └─────────┘  └─────────────┘  └─────────┘    │
//! │       │            │              │              │          │
//! │       └────────────┴──────────────┴──────────────┘          │
//! │                           │                                 │
//! │                    ┌──────┴──────┐                          │
//! │                    │ Application │                          │
//! │                    │  Services   │                          │
//! │                    └─────────────┘                          │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust
//! use arkd_core::domain::{Round, RoundConfig, Participant, VtxoRequest};
//! use bitcoin::Amount;
//!
//! // Create a new round
//! let config = RoundConfig::default();
//! let mut round = Round::new(config);
//!
//! // Rounds collect participants and their VTXO requests
//! // See individual module documentation for details
//! ```

pub mod exit;
pub mod participant;
pub mod round;
pub mod vtxo;

// Re-exports for convenience
pub use exit::{
    BoardingRequest, BoardingStatus, BoardingTransaction, CollaborativeExitRequest, Exit,
    ExitError, ExitStatus, ExitSummary, ExitType, UnilateralExitRequest,
};
pub use participant::{
    BanReason, BanStatus, Participant, ParticipantSignature, ParticipantSummary,
};
pub use round::{Round, RoundConfig, RoundError, RoundStatus, RoundSummary};
pub use vtxo::{TreePath, Vtxo, VtxoId, VtxoRequest, VtxoStatus};

/// Default VTXO expiry in blocks (~30 days at 10 min/block)
pub const DEFAULT_VTXO_EXPIRY_BLOCKS: u32 = 144 * 30;

/// Default minimum participants for a round
pub const DEFAULT_MIN_PARTICIPANTS: u32 = 2;

/// Default maximum participants for a round
pub const DEFAULT_MAX_PARTICIPANTS: u32 = 128;

/// Default exit delta (timelock for unilateral exit) in blocks (~24 hours)
pub const DEFAULT_EXIT_DELTA_BLOCKS: u32 = 144;

/// Minimum VTXO amount in satoshis (dust limit)
pub const MIN_VTXO_AMOUNT_SATS: u64 = 546;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify reasonable defaults
        assert!(DEFAULT_VTXO_EXPIRY_BLOCKS > DEFAULT_EXIT_DELTA_BLOCKS);
        assert!(DEFAULT_MIN_PARTICIPANTS >= 2);
        assert!(DEFAULT_MAX_PARTICIPANTS > DEFAULT_MIN_PARTICIPANTS);
        assert!(MIN_VTXO_AMOUNT_SATS >= 546); // Bitcoin dust limit
    }
}
