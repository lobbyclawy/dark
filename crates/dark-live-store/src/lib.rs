//! Ephemeral live-store implementations for dark round state.
//!
//! Provides [`InMemoryLiveStore`] for dev/test and `RedisLiveStore` for production.
//! Also provides higher-level round-state components: [`ArkLiveStore`] bundles
//! [`IntentsQueue`], [`ForfeitTxsStore`], [`ConfirmationStore`],
//! [`SigningSessionStore`], and [`CurrentRoundStore`].
//!
//! In addition, [`NullifierSet`] provides the authoritative spent-nullifier
//! cache (issue #534) — it is durable, concurrent, and used on the
//! transaction-validation hot path.

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "etcd")]
pub mod etcd;

pub mod nullifier_set;

#[cfg(feature = "memory")]
pub use memory::{
    ArkLiveStore, InMemoryConfirmationStore, InMemoryCurrentRoundStore, InMemoryForfeitTxsStore,
    InMemoryIntentsQueue, InMemoryLiveStore, InMemorySigningSessionStore,
};

#[cfg(feature = "redis")]
pub use self::redis::RedisLiveStore;

#[cfg(feature = "etcd")]
pub use self::etcd::EtcdLiveStore;

pub use nullifier_set::{
    InMemoryNullifierStore, Nullifier, NullifierSet, NullifierStore, NULLIFIER_LEN, SHARD_COUNT,
};

// Re-export the traits for convenience
pub use dark_core::ports::{
    ConfirmationStore, CurrentRoundStore, ForfeitTxsStore, IntentsQueue, SigningSessionStore,
};
