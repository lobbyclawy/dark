//! Ephemeral live-store implementations for arkd round state.
//!
//! Provides [`InMemoryLiveStore`] for dev/test and [`RedisLiveStore`] for production.
//! Also provides higher-level round-state components: [`ArkLiveStore`] bundles
//! [`IntentsQueue`], [`ForfeitTxsStore`], [`ConfirmationStore`],
//! [`SigningSessionStore`], and [`CurrentRoundStore`].

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "etcd")]
pub mod etcd;

#[cfg(feature = "memory")]
pub use memory::{
    ArkLiveStore, InMemoryConfirmationStore, InMemoryCurrentRoundStore, InMemoryForfeitTxsStore,
    InMemoryIntentsQueue, InMemoryLiveStore, InMemorySigningSessionStore,
};

#[cfg(feature = "redis")]
pub use self::redis::RedisLiveStore;

#[cfg(feature = "etcd")]
pub use self::etcd::EtcdLiveStore;

// Re-export the traits for convenience
pub use arkd_core::ports::{
    ConfirmationStore, CurrentRoundStore, ForfeitTxsStore, IntentsQueue, SigningSessionStore,
};
