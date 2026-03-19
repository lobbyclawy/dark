//! Repository implementations for arkd-core port traits
//!
//! Each repository implements the corresponding trait from `arkd_core::ports`
//! using SQLite or PostgreSQL (via sqlx) as the backing store.

#[cfg(feature = "sqlite")]
pub mod asset_repo;
#[cfg(feature = "sqlite")]
pub mod boarding_repo;
#[cfg(feature = "sqlite")]
pub mod checkpoint_repo;
#[cfg(feature = "sqlite")]
pub mod confirmation_store;
#[cfg(feature = "sqlite")]
pub mod conviction_repo;
#[cfg(feature = "sqlite")]
pub mod forfeit_repo;
#[cfg(feature = "sqlite")]
pub mod offchain_tx_repo;
#[cfg(feature = "sqlite")]
pub mod round_repo;
#[cfg(feature = "sqlite")]
pub mod signing_session_store;
#[cfg(feature = "sqlite")]
pub mod vtxo_repo;

#[cfg(feature = "postgres")]
pub mod offchain_tx_repo_pg;
#[cfg(feature = "postgres")]
pub mod round_repo_pg;
#[cfg(feature = "postgres")]
pub mod vtxo_repo_pg;

#[cfg(feature = "sqlite")]
pub use asset_repo::SqliteAssetRepository;
#[cfg(feature = "sqlite")]
pub use boarding_repo::SqliteBoardingRepository;
#[cfg(feature = "sqlite")]
pub use checkpoint_repo::SqliteCheckpointRepository;
#[cfg(feature = "sqlite")]
pub use confirmation_store::SqliteConfirmationStore;
#[cfg(feature = "sqlite")]
pub use conviction_repo::SqliteConvictionRepository;
#[cfg(feature = "sqlite")]
pub use forfeit_repo::SqliteForfeitRepository;
#[cfg(feature = "sqlite")]
pub use offchain_tx_repo::SqliteOffchainTxRepository;
#[cfg(feature = "sqlite")]
pub use round_repo::SqliteRoundRepository;
#[cfg(feature = "sqlite")]
pub use signing_session_store::SqliteSigningSessionStore;
#[cfg(feature = "sqlite")]
pub use vtxo_repo::SqliteVtxoRepository;

#[cfg(feature = "postgres")]
pub use offchain_tx_repo_pg::PgOffchainTxRepository;
#[cfg(feature = "postgres")]
pub use round_repo_pg::PgRoundRepository;
#[cfg(feature = "postgres")]
pub use vtxo_repo_pg::PgVtxoRepository;
