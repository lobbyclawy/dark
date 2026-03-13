//! arkd-core - Core business logic for the Ark protocol
//!
//! This crate implements the core Ark protocol logic:
//! - Round management and scheduling
//! - Intent registration and validation
//! - VTXO lifecycle management
//! - Cosigning sessions (MuSig2)
//! - Forfeit transaction handling
//! - Sweep service for expired VTXOs
//! - Exit mechanisms (collaborative, unilateral, boarding)

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod application;
pub mod boarding;
pub mod cosigning;
pub mod domain;
pub mod error;
pub mod metrics;
pub mod ports;
pub mod round_scheduler;
pub mod sweep;
pub mod validation;

#[cfg(test)]
mod proptest_tests;

pub use application::{ArkConfig, ArkService, ServiceInfo};
pub use boarding::{BoardingConfig, BoardingService, BoardingStats};
pub use cosigning::{
    CosigningManager, CosigningSession, CosigningState, ForfeitTxEntry, ForfeitTxManager,
    NonceCommitment, PartialSignature,
};
pub use domain::{
    BoardingRequest, BoardingStatus, BoardingTransaction, CollaborativeExitRequest, Exit,
    ExitError, ExitStatus, ExitSummary, ExitType, FlatTxTree, ForfeitTx, Intent, Receiver, Round,
    RoundConfig, RoundStage, RoundStats, Stage, TxTreeNode, UnilateralExitRequest, Vtxo, VtxoId,
    VtxoOutpoint,
};
pub use error::{ArkError, ArkResult};
pub use ports::{
    ArkEvent, CacheService, EventPublisher, RoundRepository, SignerService, TxBuilder,
    VtxoRepository, WalletService,
};
pub use round_scheduler::{RoundScheduler, SchedulerCommand, SchedulerConfig, SchedulerState};
pub use sweep::{SweepBatch, SweepConfig, SweepService, SweepStats};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;
