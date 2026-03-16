//! Ban/conviction system for misbehaving participants.
//!
//! Tracks participants who have been convicted of protocol violations
//! (double-spend, failure to confirm, invalid proofs) and prevents them
//! from participating in future rounds.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::error::ArkResult;
use crate::ports::BanRepository;

/// Reason a participant was banned.
#[derive(Debug, Clone)]
pub enum BanReason {
    /// Participant attempted to double-spend a VTXO.
    DoubleSpend,
    /// Participant failed to confirm during a round.
    FailedToConfirm,
    /// Participant submitted an invalid proof.
    InvalidProof,
    /// Other reason with description.
    Other(String),
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoubleSpend => write!(f, "double_spend"),
            Self::FailedToConfirm => write!(f, "failed_to_confirm"),
            Self::InvalidProof => write!(f, "invalid_proof"),
            Self::Other(reason) => write!(f, "other: {reason}"),
        }
    }
}

/// A record of a participant ban/conviction.
#[derive(Debug, Clone)]
pub struct BanRecord {
    /// Public key of the banned participant.
    pub pubkey: String,
    /// Reason for the ban.
    pub reason: BanReason,
    /// Round ID during which the violation occurred.
    pub round_id: String,
    /// Unix timestamp when the ban was created.
    pub timestamp: u64,
    /// Optional expiry timestamp. `None` means permanent.
    pub expires_at: Option<u64>,
}

/// In-memory implementation of [`BanRepository`] for testing and light deployments.
pub struct InMemoryBanRepository {
    bans: Mutex<HashMap<String, BanRecord>>,
}

impl InMemoryBanRepository {
    /// Create a new empty in-memory ban repository.
    pub fn new() -> Self {
        Self {
            bans: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryBanRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BanRepository for InMemoryBanRepository {
    async fn ban(&self, pubkey: &str, reason: BanReason, round_id: &str) -> ArkResult<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let record = BanRecord {
            pubkey: pubkey.to_string(),
            reason,
            round_id: round_id.to_string(),
            timestamp,
            expires_at: None,
        };
        self.bans
            .lock()
            .expect("ban lock poisoned")
            .insert(pubkey.to_string(), record);
        Ok(())
    }

    async fn is_banned(&self, pubkey: &str) -> ArkResult<bool> {
        let bans = self.bans.lock().expect("ban lock poisoned");
        match bans.get(pubkey) {
            None => Ok(false),
            Some(record) => {
                if let Some(expires_at) = record.expires_at {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    Ok(now < expires_at)
                } else {
                    Ok(true) // permanent ban
                }
            }
        }
    }

    async fn get_ban(&self, pubkey: &str) -> ArkResult<Option<BanRecord>> {
        let bans = self.bans.lock().expect("ban lock poisoned");
        Ok(bans.get(pubkey).cloned())
    }

    async fn unban(&self, pubkey: &str) -> ArkResult<()> {
        self.bans.lock().expect("ban lock poisoned").remove(pubkey);
        Ok(())
    }

    async fn list_banned(&self) -> ArkResult<Vec<BanRecord>> {
        let bans = self.bans.lock().expect("ban lock poisoned");
        Ok(bans.values().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ban_participant_marks_as_banned() {
        let repo = InMemoryBanRepository::new();
        let pubkey = "02abc123";
        repo.ban(pubkey, BanReason::DoubleSpend, "round-1")
            .await
            .unwrap();
        let record = repo.get_ban(pubkey).await.unwrap();
        assert!(record.is_some());
        let record = record.unwrap();
        assert_eq!(record.pubkey, pubkey);
        assert_eq!(record.round_id, "round-1");
    }

    #[tokio::test]
    async fn test_banned_participant_is_detected() {
        let repo = InMemoryBanRepository::new();
        let pubkey = "02abc123";
        assert!(!repo.is_banned(pubkey).await.unwrap());
        repo.ban(pubkey, BanReason::FailedToConfirm, "round-2")
            .await
            .unwrap();
        assert!(repo.is_banned(pubkey).await.unwrap());
    }

    #[tokio::test]
    async fn test_unban_removes_ban() {
        let repo = InMemoryBanRepository::new();
        let pubkey = "02abc123";
        repo.ban(pubkey, BanReason::InvalidProof, "round-3")
            .await
            .unwrap();
        assert!(repo.is_banned(pubkey).await.unwrap());
        repo.unban(pubkey).await.unwrap();
        assert!(!repo.is_banned(pubkey).await.unwrap());
        assert!(repo.get_ban(pubkey).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_banned_returns_all() {
        let repo = InMemoryBanRepository::new();
        repo.ban("pk1", BanReason::DoubleSpend, "r1").await.unwrap();
        repo.ban("pk2", BanReason::FailedToConfirm, "r2")
            .await
            .unwrap();
        repo.ban("pk3", BanReason::Other("spam".into()), "r3")
            .await
            .unwrap();
        let list = repo.list_banned().await.unwrap();
        assert_eq!(list.len(), 3);
        let keys: Vec<&str> = list.iter().map(|r| r.pubkey.as_str()).collect();
        assert!(keys.contains(&"pk1"));
        assert!(keys.contains(&"pk2"));
        assert!(keys.contains(&"pk3"));
    }
}
