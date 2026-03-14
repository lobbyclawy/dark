use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};

/// Nostr relay URL and key configuration.
#[derive(Debug, Clone)]
pub struct NostrConfig {
    /// WebSocket URL of the Nostr relay (e.g. `wss://relay.damus.io`)
    pub relay_url: String,
    /// 32-byte hex-encoded private key for signing Nostr events (wrapped in Secret)
    pub private_key: Secret<String>,
}

impl NostrConfig {
    /// Create a new NostrConfig.
    pub fn new(relay_url: impl Into<String>, private_key_hex: impl Into<String>) -> Self {
        Self {
            relay_url: relay_url.into(),
            private_key: Secret::new(private_key_hex.into()),
        }
    }

    /// Get the private key hex (exposes the secret).
    pub fn private_key_hex(&self) -> &str {
        self.private_key.expose_secret()
    }
}

// Custom serde for NostrConfig to handle Secret
impl Serialize for NostrConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("NostrConfig", 2)?;
        s.serialize_field("relay_url", &self.relay_url)?;
        // Note: We serialize the secret for config persistence, but it's protected in memory
        s.serialize_field("private_key_hex", self.private_key.expose_secret())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for NostrConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            relay_url: String,
            private_key_hex: String,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(NostrConfig::new(helper.relay_url, helper.private_key_hex))
    }
}

/// A Nostr event (NIP-01).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NostrEvent {
    /// Event ID (SHA-256 of the serialized event)
    pub id: String,
    /// Author public key (hex)
    pub pubkey: String,
    /// Unix timestamp of creation
    pub created_at: u64,
    /// Event kind (4 = encrypted DM per NIP-04)
    pub kind: u32,
    /// Event tags (each tag is an array of strings)
    pub tags: Vec<Vec<String>>,
    /// Event content (plaintext or encrypted)
    pub content: String,
    /// Schnorr signature (hex)
    pub sig: String,
}

impl NostrEvent {
    /// Create an unsigned event (id and sig will be empty).
    pub fn unsigned(
        pubkey: impl Into<String>,
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id: String::new(),
            pubkey: pubkey.into(),
            created_at,
            kind,
            tags,
            content: content.into(),
            sig: String::new(),
        }
    }
}

/// Nostr message types for relay communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NostrMessage {
    /// ["EVENT", `event`] - Publish an event
    Event(String, NostrEvent),
    /// ["OK", `event_id`, `accepted`, `message`] - Event acceptance response
    Ok(String, String, bool, String),
    /// ["NOTICE", `message`] - Notice from relay
    Notice(String, String),
}

impl NostrMessage {
    /// Create an EVENT message for publishing.
    pub fn event(event: NostrEvent) -> Self {
        NostrMessage::Event("EVENT".to_string(), event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nostr_config_serde() {
        let config = NostrConfig::new("wss://relay.damus.io", "a".repeat(64));
        let json = serde_json::to_string(&config).unwrap();
        let parsed: NostrConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.relay_url, "wss://relay.damus.io");
        assert_eq!(parsed.private_key_hex().len(), 64);
    }

    #[test]
    fn test_nostr_config_secret_protection() {
        let config = NostrConfig::new("wss://relay.example.com", "secret_key_12345");
        // Debug output should not reveal the secret
        let debug_output = format!("{:?}", config);
        assert!(!debug_output.contains("secret_key_12345"));
    }

    #[test]
    fn test_unsigned_event_creation() {
        let event = NostrEvent::unsigned(
            "pubkey123",
            1234567890,
            1,
            vec![vec!["e".to_string(), "event_id".to_string()]],
            "Hello, Nostr!",
        );
        assert_eq!(event.pubkey, "pubkey123");
        assert_eq!(event.created_at, 1234567890);
        assert_eq!(event.kind, 1);
        assert!(event.id.is_empty());
        assert!(event.sig.is_empty());
    }
}
