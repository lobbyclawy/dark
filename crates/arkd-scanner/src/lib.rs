//! Blockchain scanner implementations for on-chain VTXO watching.
//!
//! Provides two implementations of `BlockchainScanner`:
//! - [`NoopScanner`] — does nothing, for dev/test environments
//! - [`EsploraScanner`] — polls an Esplora HTTP API for script spends
//!
//! Additional Esplora-based services:
//! - [`EsploraFraudDetector`] — on-chain VTXO double-spend detection (#246)
//! - [`EsploraSweepService`] — expired VTXO sweep identification (#246)

pub mod esplora;
pub mod fraud;
pub mod noop;
pub mod sweep;

pub use esplora::EsploraScanner;
pub use fraud::EsploraFraudDetector;
pub use noop::NoopScanner;
pub use sweep::EsploraSweepService;

// Re-export the trait and event type for convenience
pub use arkd_core::ports::{BlockchainScanner, ScriptSpentEvent};
