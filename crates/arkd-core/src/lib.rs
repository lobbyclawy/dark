//! arkd-core - Core business logic for the Ark protocol

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod application;
pub mod domain;
pub mod error;
pub mod ports;

pub use application::{ArkConfig, ArkService, ServiceInfo};
pub use domain::{
    Exit, ExitStatus, ExitType, FlatTxTree, ForfeitTx, Intent, Receiver, Round, RoundConfig,
    RoundStage, RoundStats, Stage, TxTreeNode, Vtxo, VtxoId, VtxoOutpoint,
};
pub use error::{ArkError, ArkResult};
pub use ports::{
    ArkEvent, CacheService, EventPublisher, RoundRepository, SignerService, TxBuilder,
    VtxoRepository, WalletService,
};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;
