//! Sled-backed implementation of `dark_core::ports::ConvictionRepository`.
//!
//! Key layout:
//! - `conv::id::{id}` → serialized Conviction (primary store)
//! - `conv::round::{round_id}::{id}` → id (round index)
//! - `conv::script::{script}::{id}` → id (script index)

use crate::embedded_kv::SledKvStore;
use async_trait::async_trait;
use dark_core::domain::{Conviction, ConvictionKind, CrimeType};
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::ConvictionRepository;
use std::sync::Arc;

/// Sled-backed conviction repository.
pub struct SledConvictionRepository {
    store: Arc<SledKvStore>,
}

impl SledConvictionRepository {
    /// Create a new sled-backed conviction repository.
    pub fn new(store: Arc<SledKvStore>) -> Self {
        Self { store }
    }

    fn primary_key(id: &str) -> Vec<u8> {
        format!("conv::id::{id}").into_bytes()
    }

    fn round_index_key(round_id: &str, id: &str) -> Vec<u8> {
        format!("conv::round::{round_id}::{id}").into_bytes()
    }

    fn script_index_key(script: &str, id: &str) -> Vec<u8> {
        format!("conv::script::{script}::{id}").into_bytes()
    }

    fn serialize(c: &Conviction) -> ArkResult<Vec<u8>> {
        serde_json::to_vec(&ConvictionDto::from(c))
            .map_err(|e| ArkError::DatabaseError(format!("serialize conviction: {e}")))
    }

    fn deserialize(bytes: &[u8]) -> ArkResult<Conviction> {
        let dto: ConvictionDto = serde_json::from_slice(bytes)
            .map_err(|e| ArkError::DatabaseError(format!("deserialize conviction: {e}")))?;
        Ok(dto.into_conviction())
    }

    fn store_conviction_inner(&self, conviction: &Conviction) -> ArkResult<()> {
        let data = Self::serialize(conviction)?;

        // Primary record
        self.store
            .set(&Self::primary_key(&conviction.id), &data)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        // Round index
        if !conviction.round_id.is_empty() {
            self.store
                .set(
                    &Self::round_index_key(&conviction.round_id, &conviction.id),
                    conviction.id.as_bytes(),
                )
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        // Script index
        if !conviction.script.is_empty() {
            self.store
                .set(
                    &Self::script_index_key(&conviction.script, &conviction.id),
                    conviction.id.as_bytes(),
                )
                .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        }

        Ok(())
    }

    fn get_by_id(&self, id: &str) -> ArkResult<Option<Conviction>> {
        match self
            .store
            .get(&Self::primary_key(id))
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => Ok(Some(Self::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ConvictionRepository for SledConvictionRepository {
    async fn store(&self, conviction: Conviction) -> ArkResult<()> {
        self.store_conviction_inner(&conviction)
    }

    async fn get_by_ids(&self, ids: &[String]) -> ArkResult<Vec<Conviction>> {
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(c) = self.get_by_id(id)? {
                result.push(c);
            }
        }
        Ok(result)
    }

    async fn get_in_range(&self, from: i64, to: i64) -> ArkResult<Vec<Conviction>> {
        // Full scan of primary keys — acceptable for sled light-mode use
        let prefix = b"conv::id::";
        let entries = self
            .store
            .scan_prefix(prefix)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for (_, v) in entries {
            let c = Self::deserialize(&v)?;
            if c.created_at >= from && c.created_at <= to {
                result.push(c);
            }
        }
        result.sort_by_key(|c| c.created_at);
        Ok(result)
    }

    async fn get_by_round(&self, round_id: &str) -> ArkResult<Vec<Conviction>> {
        let prefix = format!("conv::round::{round_id}::").into_bytes();
        let entries = self
            .store
            .scan_prefix(&prefix)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let mut result = Vec::new();
        for (_, id_bytes) in entries {
            let id = String::from_utf8(id_bytes)
                .map_err(|e| ArkError::DatabaseError(format!("invalid id: {e}")))?;
            if let Some(c) = self.get_by_id(&id)? {
                result.push(c);
            }
        }
        result.sort_by_key(|c| c.created_at);
        Ok(result)
    }

    async fn get_active_by_script(&self, script: &str) -> ArkResult<Vec<Conviction>> {
        let prefix = format!("conv::script::{script}::").into_bytes();
        let entries = self
            .store
            .scan_prefix(&prefix)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut result = Vec::new();
        for (_, id_bytes) in entries {
            let id = String::from_utf8(id_bytes)
                .map_err(|e| ArkError::DatabaseError(format!("invalid id: {e}")))?;
            if let Some(c) = self.get_by_id(&id)? {
                if !c.pardoned && (c.expires_at == 0 || c.expires_at > now) {
                    result.push(c);
                }
            }
        }
        result.sort_by_key(|c| c.created_at);
        Ok(result)
    }

    async fn pardon(&self, id: &str) -> ArkResult<()> {
        let mut c = self
            .get_by_id(id)?
            .ok_or_else(|| ArkError::NotFound(format!("Conviction {id} not found")))?;
        c.pardoned = true;
        // Re-serialize primary record (indexes unchanged)
        let data = Self::serialize(&c)?;
        self.store
            .set(&Self::primary_key(id), &data)
            .map_err(|e| ArkError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DTO for JSON serialization (domain types don't derive Serialize/Deserialize)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize)]
struct ConvictionDto {
    id: String,
    kind: i32,
    created_at: i64,
    expires_at: i64,
    pardoned: bool,
    script: String,
    crime_type: String,
    round_id: String,
    reason: String,
}

impl From<&Conviction> for ConvictionDto {
    fn from(c: &Conviction) -> Self {
        Self {
            id: c.id.clone(),
            kind: match c.kind {
                ConvictionKind::Unspecified => 0,
                ConvictionKind::Script => 1,
            },
            created_at: c.created_at,
            expires_at: c.expires_at,
            pardoned: c.pardoned,
            script: c.script.clone(),
            crime_type: c.crime_type.to_string(),
            round_id: c.round_id.clone(),
            reason: c.reason.clone(),
        }
    }
}

impl ConvictionDto {
    fn into_conviction(self) -> Conviction {
        let kind = match self.kind {
            1 => ConvictionKind::Script,
            _ => ConvictionKind::Unspecified,
        };
        let crime_type = match self.crime_type.as_str() {
            "musig2_nonce_submission" => CrimeType::Musig2NonceSubmission,
            "musig2_signature_submission" => CrimeType::Musig2SignatureSubmission,
            "musig2_invalid_signature" => CrimeType::Musig2InvalidSignature,
            "forfeit_submission" => CrimeType::ForfeitSubmission,
            "forfeit_invalid_signature" => CrimeType::ForfeitInvalidSignature,
            "boarding_input_submission" => CrimeType::BoardingInputSubmission,
            "manual_ban" => CrimeType::ManualBan,
            "double_spend" => CrimeType::DoubleSpend,
            _ => CrimeType::Unspecified,
        };

        Conviction {
            id: self.id,
            kind,
            created_at: self.created_at,
            expires_at: self.expires_at,
            pardoned: self.pardoned,
            script: self.script,
            crime_type,
            round_id: self.round_id,
            reason: self.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Arc<SledKvStore> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(SledKvStore::open(dir.path()).unwrap())
    }

    #[tokio::test]
    async fn test_store_and_get_by_ids() {
        let repo = SledConvictionRepository::new(make_store());

        let conv = Conviction::manual_ban("script-abc", "spamming", 3600);
        let id = conv.id.clone();
        repo.store(conv).await.unwrap();

        let found = repo.get_by_ids(std::slice::from_ref(&id)).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].script, "script-abc");
        assert_eq!(found[0].reason, "spamming");
        assert_eq!(found[0].crime_type, CrimeType::ManualBan);
    }

    #[tokio::test]
    async fn test_get_by_ids_not_found() {
        let repo = SledConvictionRepository::new(make_store());
        let found = repo.get_by_ids(&["nonexistent".into()]).await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn test_get_by_round() {
        let repo = SledConvictionRepository::new(make_store());

        let mut c1 = Conviction::manual_ban("s1", "r1", 0);
        c1.round_id = "round-1".to_string();
        let mut c2 = Conviction::manual_ban("s2", "r2", 0);
        c2.round_id = "round-1".to_string();
        let mut c3 = Conviction::manual_ban("s3", "r3", 0);
        c3.round_id = "round-2".to_string();

        repo.store(c1).await.unwrap();
        repo.store(c2).await.unwrap();
        repo.store(c3).await.unwrap();

        let round1 = repo.get_by_round("round-1").await.unwrap();
        assert_eq!(round1.len(), 2);
    }

    #[tokio::test]
    async fn test_get_active_by_script() {
        let repo = SledConvictionRepository::new(make_store());

        // Active permanent ban
        let c1 = Conviction::manual_ban("script-x", "permanent ban", 0);
        repo.store(c1).await.unwrap();

        // Active time-limited ban (1 hour from now)
        let c2 = Conviction::manual_ban("script-x", "temp ban", 3600);
        repo.store(c2).await.unwrap();

        // Pardoned ban
        let mut c3 = Conviction::manual_ban("script-x", "pardoned", 0);
        c3.pardoned = true;
        repo.store(c3).await.unwrap();

        let active = repo.get_active_by_script("script-x").await.unwrap();
        assert_eq!(active.len(), 2); // permanent + temp, not pardoned
    }

    #[tokio::test]
    async fn test_pardon() {
        let repo = SledConvictionRepository::new(make_store());

        let conv = Conviction::manual_ban("script-y", "bad", 0);
        let id = conv.id.clone();
        repo.store(conv).await.unwrap();

        repo.pardon(&id).await.unwrap();

        let found = repo.get_by_ids(&[id]).await.unwrap();
        assert!(found[0].pardoned);
    }

    #[tokio::test]
    async fn test_pardon_not_found() {
        let repo = SledConvictionRepository::new(make_store());
        let result = repo.pardon("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_in_range() {
        let repo = SledConvictionRepository::new(make_store());

        let conv = Conviction::manual_ban("s1", "reason", 0);
        let created = conv.created_at;
        repo.store(conv).await.unwrap();

        let found = repo.get_in_range(created - 1, created + 1).await.unwrap();
        assert_eq!(found.len(), 1);

        let not_found = repo
            .get_in_range(created + 100, created + 200)
            .await
            .unwrap();
        assert!(not_found.is_empty());
    }
}
