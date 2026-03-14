//! Nostr-based notifier implementing NIP-04 encrypted DMs.

use std::time::{SystemTime, UNIX_EPOCH};

use arkd_core::error::{ArkError, ArkResult};
use arkd_core::ports::Notifier;
use async_trait::async_trait;

use crate::crypto::{nip04_encrypt, sign_event, NostrKeypair};
use crate::relay::RelayConnection;
use crate::types::{NostrConfig, NostrEvent};

/// Nostr-based notifier for sending NIP-04 encrypted DMs.
///
/// Implements the `Notifier` port from arkd-core to send notifications
/// to users via Nostr relays.
pub struct NostrNotifier {
    config: NostrConfig,
    keypair: NostrKeypair,
}

impl NostrNotifier {
    /// Create a new `NostrNotifier` with the given configuration.
    pub fn new(config: NostrConfig) -> Result<Self, ArkError> {
        let keypair = NostrKeypair::from_hex(config.private_key_hex())
            .map_err(|e| ArkError::Internal(format!("Invalid Nostr private key: {}", e)))?;
        Ok(Self { config, keypair })
    }

    /// Get the notifier's public key (hex).
    pub fn pubkey(&self) -> String {
        self.keypair.pubkey_hex()
    }

    /// Create and sign a NIP-04 encrypted DM event.
    fn create_dm_event(
        &self,
        recipient_pubkey: &str,
        plaintext: &str,
    ) -> Result<NostrEvent, ArkError> {
        // Compute shared secret for NIP-04
        let shared_secret = self
            .keypair
            .compute_shared_secret(recipient_pubkey)
            .map_err(|e| ArkError::Internal(format!("Failed to compute shared secret: {}", e)))?;

        // Encrypt the message
        let encrypted_content = nip04_encrypt(plaintext, &shared_secret)
            .map_err(|e| ArkError::Internal(format!("NIP-04 encryption failed: {}", e)))?;

        // Get current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Create the event with NIP-04 DM kind (4)
        let mut event = NostrEvent::unsigned(
            self.keypair.pubkey_hex(),
            created_at,
            4, // Encrypted DM
            vec![vec!["p".to_string(), recipient_pubkey.to_string()]],
            encrypted_content,
        );

        // Sign the event
        sign_event(&mut event, &self.keypair)
            .map_err(|e| ArkError::Internal(format!("Failed to sign Nostr event: {}", e)))?;

        Ok(event)
    }

    /// Publish an event to the configured relay.
    async fn publish_event(&self, event: &NostrEvent) -> ArkResult<()> {
        let relay = RelayConnection::new(&self.config.relay_url)
            .map_err(|e| ArkError::Internal(format!("Invalid relay URL: {}", e)))?;

        let result = relay
            .publish(event)
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to publish to relay: {}", e)))?;

        if !result.accepted {
            tracing::warn!(
                relay = %self.config.relay_url,
                event_id = %result.event_id,
                message = %result.message,
                "Relay rejected event"
            );
        } else {
            tracing::info!(
                relay = %self.config.relay_url,
                event_id = %result.event_id,
                "Event published successfully"
            );
        }

        Ok(())
    }
}

#[async_trait]
impl Notifier for NostrNotifier {
    async fn notify(&self, recipient_pubkey: &str, subject: &str, body: &str) -> ArkResult<()> {
        let message = format!("{}: {}", subject, body);
        let event = self.create_dm_event(recipient_pubkey, &message)?;

        tracing::debug!(
            relay = %self.config.relay_url,
            recipient = %recipient_pubkey,
            event_id = %event.id,
            "Sending Nostr DM notification"
        );

        self.publish_event(&event).await
    }

    async fn notify_vtxo_expiry(&self, pubkey: &str, vtxo_id: &str, blocks: u32) -> ArkResult<()> {
        self.notify(
            pubkey,
            "VTXO Expiry Warning",
            &format!("VTXO {} expires in {} blocks. Sweep soon.", vtxo_id, blocks),
        )
        .await
    }

    async fn notify_round_complete(&self, round_id: &str, vtxo_count: u32) -> ArkResult<()> {
        // Round completion is a broadcast notification - log it
        // In the future, this could publish to a public channel or topic
        tracing::info!(
            round_id,
            vtxo_count,
            "Round complete (broadcast notification not yet implemented for Nostr)"
        );
        Ok(())
    }
}

/// Builder for creating a NostrNotifier with optional configuration.
pub struct NostrNotifierBuilder {
    relay_url: String,
    private_key_hex: String,
}

impl NostrNotifierBuilder {
    /// Create a new builder with required parameters.
    pub fn new(relay_url: impl Into<String>, private_key_hex: impl Into<String>) -> Self {
        Self {
            relay_url: relay_url.into(),
            private_key_hex: private_key_hex.into(),
        }
    }

    /// Build the notifier.
    pub fn build(self) -> Result<NostrNotifier, ArkError> {
        let config = NostrConfig::new(self.relay_url, self.private_key_hex);
        NostrNotifier::new(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::ports::NoopNotifier;

    // Test keypair
    const TEST_PRIVKEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const TEST_RECIPIENT: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn test_nostr_notifier_new() {
        let config = NostrConfig::new("wss://relay.example.com", TEST_PRIVKEY);
        let notifier = NostrNotifier::new(config).unwrap();
        assert_eq!(notifier.pubkey().len(), 64);
    }

    #[test]
    fn test_nostr_notifier_invalid_key() {
        let config = NostrConfig::new("wss://relay.example.com", "invalid_key");
        let result = NostrNotifier::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_dm_event() {
        let config = NostrConfig::new("wss://relay.example.com", TEST_PRIVKEY);
        let notifier = NostrNotifier::new(config).unwrap();

        let event = notifier
            .create_dm_event(TEST_RECIPIENT, "Hello, Ark!")
            .unwrap();

        // Event should be properly signed
        assert!(!event.id.is_empty());
        assert!(!event.sig.is_empty());
        assert_eq!(event.kind, 4); // DM
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.tags[0][0], "p");
        assert_eq!(event.tags[0][1], TEST_RECIPIENT);

        // Content should be encrypted (base64?iv=base64)
        assert!(event.content.contains("?iv="));
    }

    #[test]
    fn test_nostr_notifier_builder() {
        let notifier = NostrNotifierBuilder::new("wss://relay.damus.io", TEST_PRIVKEY)
            .build()
            .unwrap();

        assert_eq!(notifier.pubkey().len(), 64);
    }

    #[tokio::test]
    async fn test_noop_notifier_returns_ok() {
        let noop = NoopNotifier;
        assert!(noop.notify("pk", "subj", "body").await.is_ok());
        assert!(noop.notify_vtxo_expiry("pk", "vtxo1", 10).await.is_ok());
        assert!(noop.notify_round_complete("round1", 5).await.is_ok());
    }

    #[tokio::test]
    async fn test_notify_vtxo_expiry_format() {
        let config = NostrConfig::new("wss://relay.example.com", TEST_PRIVKEY);
        let notifier = NostrNotifier::new(config).unwrap();

        // Create the event to verify formatting (don't actually publish)
        let event = notifier
            .create_dm_event(
                TEST_RECIPIENT,
                "VTXO Expiry Warning: VTXO vtxo-abc expires in 100 blocks. Sweep soon.",
            )
            .unwrap();

        assert_eq!(event.kind, 4);
        assert!(event.content.contains("?iv=")); // Encrypted
    }
}
