//! Sled-backed repository implementations for arkd-core port traits.
//!
//! These provide lightweight, embedded alternatives to the SQLite/Postgres
//! repositories — useful for light-mode deployments that don't need a full
//! relational database.

pub mod conviction_repo;
pub mod event_store;
pub mod scheduled_session_repo;

pub use conviction_repo::SledConvictionRepository;
pub use event_store::SledEventStore;
pub use scheduled_session_repo::SledScheduledSessionRepository;
