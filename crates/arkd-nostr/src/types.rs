use serde::{Deserialize, Serialize};

/// Nostr relay URL and key configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrConfig {
    /// WebSocket URL of the Nostr relay (e.g. `wss://relay.damus.io`)
    pub relay_url: String,
    /// 32-byte hex-encoded private key for signing Nostr events
    pub private_key_hex: String,
}

/// A Nostr event (NIP-01).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    /// Event ID (SHA-256 of the serialized event)
    pub id: String,
    /// Author public key (hex)
    pub pubkey: String,
    /// Unix timestamp of creation
    pub created_at: u64,
    /// Event kind (4 = encrypted DM per NIP-04)
    pub kind: u32,
    /// Event tags
    pub tags: Vec<Vec<String>>,
    /// Event content (plaintext or encrypted)
    pub content: String,
    /// Schnorr signature (hex)
    pub sig: String,
}
