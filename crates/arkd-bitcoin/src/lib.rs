//! arkd-bitcoin - Bitcoin primitives and utilities
//!
//! This crate provides Bitcoin-specific functionality:
//! - Transaction building and signing
//! - Script construction (covenant scripts, timelocks)
//! - UTXO management
//! - RPC client integration

pub mod bip322;
pub mod connector;
pub mod error;
pub mod exit;
pub mod forfeit;
pub mod rpc;
pub mod script;
pub mod transaction;
pub mod tree;
pub mod utxo;

pub use bitcoin;
pub use connector::{ConnectorError, ConnectorNode, ConnectorOutput, ConnectorTree};
pub use error::{BitcoinError, BitcoinResult};
pub use forfeit::{ForfeitError, ForfeitTx, SignedForfeitTx};
