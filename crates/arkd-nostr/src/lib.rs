//! arkd-nostr - Nostr integration for arkd-rs
//!
//! This crate provides Nostr-based notifications for Ark protocol events,
//! implementing NIP-04 encrypted DMs for secure user notifications.
//!
//! # Features
//!
//! - **NIP-04 Encryption**: Secure encrypted direct messages
//! - **Schnorr Signing**: BIP-340 compliant event signatures
//! - **WebSocket Relays**: Connect to any Nostr relay
//! - **Notifier Port**: Implements `arkd_core::ports::Notifier`
//!
//! # Example
//!
//! ```rust,ignore
//! use arkd_nostr::{NostrNotifier, NostrConfig};
//! use arkd_core::ports::Notifier;
//!
//! let config = NostrConfig::new(
//!     "wss://relay.damus.io",
//!     "your_private_key_hex",
//! );
//! let notifier = NostrNotifier::new(config)?;
//!
//! // Send a notification
//! notifier.notify(
//!     "recipient_pubkey_hex",
//!     "VTXO Expiry",
//!     "Your VTXO expires soon!",
//! ).await?;
//! ```

pub mod crypto;
pub mod notifier;
pub mod relay;
pub mod types;

pub use crypto::{
    compute_event_id, nip04_decrypt, nip04_encrypt, sign_event, CryptoError, NostrKeypair,
};
pub use notifier::{NostrNotifier, NostrNotifierBuilder};
pub use relay::{publish_to_relays, PublishResult, RelayConnection, RelayError};
pub use types::{NostrConfig, NostrEvent, NostrMessage};
