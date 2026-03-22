//! dark-core - Core business logic for the Ark protocol
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

pub mod alerts_manager;
pub mod application;
pub mod boarding;
pub mod cosigning;
pub mod domain;
pub mod error;
pub mod event_bus;
pub mod fraud_service;
pub mod metrics;
pub mod multi_signer;
pub mod ports;
pub mod round_loop;
pub mod round_report;
pub mod round_scheduler;
pub mod signer;
pub mod sweep;
pub mod sweeper;
pub mod tx_builder_impl;
pub mod tx_decoder_impl;
pub mod validation;

#[cfg(test)]
mod proptest_tests;

pub use alerts_manager::PrometheusAlertsManager;
pub use application::{ArkConfig, ArkService, ServiceInfo};
pub use boarding::{BoardingConfig, BoardingService, BoardingStats};
pub use cosigning::{
    CosigningManager, CosigningSession, CosigningState, ForfeitTxEntry, ForfeitTxManager,
    NonceCommitment, PartialSignature,
};
pub use domain::config_service::StaticConfigService;
pub use domain::indexer::RepositoryIndexer;
pub use domain::{
    Asset, AssetIssuance, BanReason, BanRecord, BoardingRequest, BoardingStatus,
    BoardingTransaction, CheckpointTx, CollaborativeExitRequest, Conviction, ConvictionKind,
    CrimeType, Exit, ExitError, ExitStatus, ExitSummary, ExitType, FlatTxTree, ForfeitRecord,
    ForfeitTx, InMemoryBanRepository, Intent, Receiver, Round, RoundConfig, RoundStage, RoundStats,
    ScheduledSessionConfig, Stage, TxTreeNode, UnilateralExitRequest, Vtxo, VtxoId, VtxoOutpoint,
    DEFAULT_CHECKPOINT_EXIT_DELAY, DEFAULT_EVENT_CHANNEL_CAPACITY,
};
pub use error::{ArkError, ArkResult};
pub use event_bus::{FilteredSubscriber, TokioBroadcastEventBus};
pub use multi_signer::MultiSigner;
pub use ports::ConfigService;
pub use ports::{
    AlertTopic, Alerts, ArkEvent, AssetRepository, BanRepository, BatchFinalizedAlert,
    BlockchainScanner, CacheService, CheckpointRepository, ConvictionRepository, DecodedTx,
    DecodedTxIn, DecodedTxOut, EnvUnlocker, EventPublisher, FeeManagerService, ForfeitRepository,
    FraudDetector, IndexerService, IndexerStats, LoggingEventPublisher, NoopAlerts,
    NoopBlockchainScanner, NoopCheckpointRepository, NoopConvictionRepository, NoopFeeManager,
    NoopForfeitRepository, NoopFraudDetector, NoopIndexerService, NoopOffchainTxRepository,
    NoopScheduledSessionRepository, NoopSweepService, NoopTxDecoder, OffchainTxRepository,
    RoundRepository, ScheduledSessionRepository, ScriptSpentEvent, SignerService, SweepResult,
    SweepService, TxBuilder, TxDecoder, Unlocker, VtxoRepository, WalletBalance, WalletService,
};
pub use round_loop::spawn_round_loop;
pub use round_report::RoundReport;
pub use round_scheduler::{RoundScheduler, SchedulerCommand, SchedulerConfig, SchedulerState};
pub use signer::LocalSigner;
pub use sweep::{SweepBatch, SweepConfig, SweepRunner, SweepStats, TxBuilderSweepService};
pub use sweeper::Sweeper;
// Re-export `BitcoinTxDecoder` so downstream crates can use it as `dark_core::BitcoinTxDecoder`.
pub use dark_bitcoin::BitcoinTxDecoder;
// Re-export `LocalTxBuilder` for use in main server binary.
pub use dark_bitcoin::LocalTxBuilder;

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;
