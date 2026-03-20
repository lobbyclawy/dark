//! dark-client — gRPC client library and SDK for dark.
//!
//! Provides a typed Rust client for the Ark protocol server, plus a
//! full client SDK with wallet, block explorer, and state management.
//!
//! # Quick Start — SDK
//!
//! ```no_run
//! use dark_client::sdk::ArkSdk;
//! use bitcoin::Network;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut sdk = ArkSdk::generate(
//!         "http://localhost:50051",
//!         "http://localhost:3000",
//!         Network::Regtest,
//!     );
//!     sdk.init().await?;
//!
//!     let balance = sdk.balance().await?;
//!     println!("Offchain: {} sats", balance.offchain.total);
//!
//!     let vtxos = sdk.list_vtxos().await?;
//!     println!("VTXOs: {}", vtxos.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Low-Level Transport
//!
//! ```no_run
//! use dark_client::ArkClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut client = ArkClient::new("http://localhost:50051");
//!     client.connect().await?;
//!
//!     let info = client.get_info().await?;
//!     println!("Server: {} ({})", info.pubkey, info.network);
//!
//!     let vtxos = client.list_vtxos("02abc...").await?;
//!     for vtxo in vtxos {
//!         println!("VTXO: {} ({} sats)", vtxo.id, vtxo.amount);
//!     }
//!
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod error;
pub mod explorer;
pub mod sdk;
pub mod store;
pub mod types;
pub mod wallet;

pub use client::{ArkClient, OffchainTxResult, RedeemBranch};
pub use error::{ClientError, ClientResult};
pub use types::{
    Asset, AssetMetadata, Balance, BatchEvent, BatchTxRes, BoardingAddress, ControlAssetOption,
    ExistingControlAsset, Intent, IssueAssetResult, LockedAmount, NewControlAsset, OffchainAddress,
    OffchainBalance, OnchainBalance, RoundInfo, RoundSummary, ServerInfo, TxEvent, TxResult, Vtxo,
};
