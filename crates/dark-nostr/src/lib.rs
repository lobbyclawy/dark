//! dark-nostr - Nostr integration for dark
//!
//! This crate provides Nostr-based notifications for Ark protocol events,
//! implementing NIP-04 encrypted DMs for secure user notifications.
//!
//! # Features
//!
//! - **NIP-04 Encryption**: Secure encrypted direct messages
//! - **Schnorr Signing**: BIP-340 compliant event signatures
//! - **WebSocket Relays**: Connect to any Nostr relay
//! - **Notifier Port**: Implements `dark_core::ports::Notifier`
//!
//! # Example
//!
//! ```rust,no_run
//! use dark_nostr::{NostrNotifier, NostrConfig};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = NostrConfig::new(
//!     "wss://relay.damus.io",
//!     "your_private_key_hex",
//! );
//! let notifier = NostrNotifier::new(config)?;
//!
//! // Send a notification (requires async runtime)
//! # let _ = notifier;
//! # Ok(()) }
//! ```

pub mod crypto;
pub mod notification_service;
pub mod notifier;
pub mod relay;
pub mod types;

pub use crypto::{
    compute_event_id, nip04_decrypt, nip04_encrypt, sign_event, CryptoError, NostrKeypair,
};
pub use notification_service::LoggingNotificationService;
pub use notifier::{NostrNotifier, NostrNotifierBuilder};
pub use relay::{publish_to_relays, PublishResult, RelayConnection, RelayError};
pub use types::{NostrConfig, NostrEvent, NostrMessage};
