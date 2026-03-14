use crate::types::NostrConfig;
use arkd_core::error::ArkResult;
use arkd_core::ports::Notifier;
use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// Nostr-based notifier implementing NIP-04 encrypted DMs.
///
/// Currently a stub that logs notifications; actual relay connection
/// and NIP-04 encryption will be wired in a follow-up.
pub struct NostrNotifier {
    config: NostrConfig,
}

impl NostrNotifier {
    /// Create a new `NostrNotifier` with the given configuration.
    pub fn new(config: NostrConfig) -> Self {
        Self { config }
    }

    /// Compute a deterministic event ID (SHA-256 of serialized event data).
    ///
    /// This follows the NIP-01 serialization format for computing event IDs.
    pub fn compute_event_id(pubkey: &str, created_at: u64, kind: u32, content: &str) -> String {
        let data = format!(
            "[0,\"{}\",{},{},\"\",\"{}\"]",
            pubkey, created_at, kind, content
        );
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[async_trait]
impl Notifier for NostrNotifier {
    async fn notify(&self, recipient_pubkey: &str, subject: &str, body: &str) -> ArkResult<()> {
        let content = format!("{}: {}", subject, body);
        let id = Self::compute_event_id(recipient_pubkey, 0, 4, &content);
        tracing::info!(
            relay = %self.config.relay_url,
            recipient = %recipient_pubkey,
            event_id = %id,
            "Nostr notification (stub — relay connection not yet wired)"
        );
        // TODO: actually connect to relay and publish NIP-04 event
        Ok(())
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
        tracing::info!(
            round_id,
            vtxo_count,
            "Round complete notification (broadcast stub)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::ports::NoopNotifier;

    #[test]
    fn test_nostr_config_serde() {
        let config = NostrConfig {
            relay_url: "wss://relay.damus.io".to_string(),
            private_key_hex: "a".repeat(64),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: NostrConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.relay_url, "wss://relay.damus.io");
        assert_eq!(parsed.private_key_hex.len(), 64);
    }

    #[test]
    fn test_compute_event_id_deterministic() {
        let id1 = NostrNotifier::compute_event_id("abc123", 1000, 4, "hello");
        let id2 = NostrNotifier::compute_event_id("abc123", 1000, 4, "hello");
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // SHA-256 hex

        // Different content → different ID
        let id3 = NostrNotifier::compute_event_id("abc123", 1000, 4, "world");
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn test_notify_vtxo_expiry_format() {
        let notifier = NostrNotifier::new(NostrConfig {
            relay_url: "wss://test.relay".to_string(),
            private_key_hex: "b".repeat(64),
        });
        // Should not error (stub just logs)
        let result = notifier
            .notify_vtxo_expiry("pubkey123", "vtxo-abc", 100)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_noop_notifier_returns_ok() {
        let noop = NoopNotifier;
        assert!(noop.notify("pk", "subj", "body").await.is_ok());
        assert!(noop.notify_vtxo_expiry("pk", "vtxo1", 10).await.is_ok());
        assert!(noop.notify_round_complete("round1", 5).await.is_ok());
    }

    #[test]
    fn test_nostr_notifier_new() {
        let config = NostrConfig {
            relay_url: "wss://relay.example.com".to_string(),
            private_key_hex: "c".repeat(64),
        };
        let notifier = NostrNotifier::new(config.clone());
        assert_eq!(notifier.config.relay_url, "wss://relay.example.com");
        assert_eq!(notifier.config.private_key_hex, "c".repeat(64));
    }
}
