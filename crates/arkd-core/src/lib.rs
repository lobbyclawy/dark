//! arkd-core - Core business logic for the Ark protocol
//!
//! This crate implements the core functionality of the Ark protocol,
//! a Bitcoin Layer 2 scaling solution.
//!
//! # Overview
//!
//! The Ark protocol enables scalable Bitcoin payments through:
//!
//! - **VTXOs (Virtual Transaction Outputs)**: Off-chain Bitcoin outputs
//!   that can be transferred instantly without on-chain transactions
//!
//! - **Rounds**: Batching mechanism that settles multiple VTXO operations
//!   in a single on-chain transaction, dramatically reducing fees
//!
//! - **Exits**: Mechanisms for users to withdraw their VTXOs to on-chain
//!   Bitcoin, either collaboratively (fast) or unilaterally (trustless)
//!
//! # Architecture
//!
//! This crate follows hexagonal architecture (ports & adapters):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        arkd-core                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │                 Application Services                 │   │
//! │  │  (ArkService, RoundService, ExitService, etc.)      │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                           │                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │                   Domain Models                      │   │
//! │  │  (VTXO, Round, Participant, Exit)                   │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! │                           │                                 │
//! │  ┌─────────────────────────────────────────────────────┐   │
//! │  │                      Ports                           │   │
//! │  │  (WalletService, DatabaseService, BitcoinRpc, etc.) │   │
//! │  └─────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//!              External Adapters (arkd-wallet, arkd-db, etc.)
//! ```
//!
//! # Modules
//!
//! - [`domain`]: Core business entities (VTXO, Round, Participant, Exit)
//! - [`ports`]: Interfaces for external services (traits)
//! - [`application`]: Use cases and orchestration
//! - [`error`]: Error types
//!
//! # Example
//!
//! ```rust,ignore
//! use arkd_core::{
//!     application::{ArkService, ArkConfig},
//!     domain::{Round, RoundConfig, Participant},
//! };
//!
//! // Create service with dependency injection
//! let service = ArkService::new(
//!     wallet,
//!     database,
//!     bitcoin_rpc,
//!     cache,
//!     events,
//!     ArkConfig::default(),
//! );
//!
//! // Start a new round
//! let round = service.start_round().await?;
//!
//! // Register participants
//! service.register_participant(participant).await?;
//! ```
//!
//! # Feature Flags
//!
//! This crate currently has no optional features.

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod application;
pub mod domain;
pub mod error;
pub mod ports;

// Re-exports for convenience
pub use application::{ArkConfig, ArkService, RoundStatusInfo, ServiceStatus};
pub use domain::{
    Exit, ExitStatus, ExitType, Participant, Round, RoundConfig, RoundStatus, TreePath, Vtxo,
    VtxoId, VtxoRequest, VtxoStatus,
};
pub use error::{ArkError, ArkResult};
pub use ports::{
    ArkEvent, BitcoinRpcService, CacheService, DatabaseService, EventPublisher, WalletService,
};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol version identifier
pub const PROTOCOL_VERSION: u32 = 1;
