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
pub mod signing;
pub mod tapscript;
pub mod transaction;
pub mod tree;
pub mod tx_builder;
pub mod tx_decoder;
pub mod utxo;

pub use bitcoin;
pub use connector::{ConnectorError, ConnectorNode, ConnectorOutput, ConnectorTree};
pub use error::{BitcoinError, BitcoinResult};
pub use forfeit::{ForfeitError, ForfeitTx, SignedForfeitTx};
pub use signing::{
    aggregate_nonces, aggregate_signatures, build_key_agg_ctx, create_partial_sig, generate_nonce,
    sign_full_session, verify_partial_sig,
};
pub use tapscript::{build_vtxo_taproot, vtxo_collaborative_script, vtxo_expiry_script};
pub use tx_builder::LocalTxBuilder;
pub use tx_decoder::BitcoinTxDecoder;
