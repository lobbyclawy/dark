//! Ephemeral live-store implementations for arkd round state.
//!
//! Provides [`InMemoryLiveStore`] for dev/test and [`RedisLiveStore`] for production.

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "memory")]
pub use memory::InMemoryLiveStore;

#[cfg(feature = "redis")]
pub use self::redis::RedisLiveStore;
