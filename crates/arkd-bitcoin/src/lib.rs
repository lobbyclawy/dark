///! arkd-bitcoin - Bitcoin primitives and utilities
///!
///! This crate provides Bitcoin-specific functionality:
///! - Transaction building and signing
///! - Script construction (covenant scripts, timelocks)
///! - UTXO management
///! - RPC client integration

pub mod transaction;
pub mod script;
pub mod utxo;
pub mod rpc;

pub use bitcoin;
