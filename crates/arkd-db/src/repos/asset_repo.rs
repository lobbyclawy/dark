//! SQLite-backed asset repository implementation.
//!
//! Implements [`AssetRepository`] for persistent asset storage.

use arkd_core::domain::asset::{Asset, AssetIssuance};
use arkd_core::error::ArkResult;
use arkd_core::ports::AssetRepository;
use async_trait::async_trait;
use sqlx::SqlitePool;
use std::collections::HashMap;

/// SQLite-backed asset repository.
pub struct SqliteAssetRepository {
    pool: SqlitePool,
}

impl SqliteAssetRepository {
    /// Create a new `SqliteAssetRepository` with the given connection pool.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Run the asset-specific migration (creates tables if not present).
    pub async fn run_migration(&self) -> ArkResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                amount INTEGER NOT NULL,
                issuer_pubkey TEXT NOT NULL,
                max_supply INTEGER,
                metadata TEXT NOT NULL DEFAULT \'{}\'
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| arkd_core::ArkError::Internal(format!("Asset migration failed: {e}")))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS asset_issuances (
                txid TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                issuer_pubkey TEXT NOT NULL,
                control_asset_id TEXT,
                metadata TEXT NOT NULL DEFAULT \'{}\'
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            arkd_core::ArkError::Internal(format!("Asset issuance migration failed: {e}"))
        })?;

        Ok(())
    }
}

#[async_trait]
impl AssetRepository for SqliteAssetRepository {
    async fn store_asset(&self, asset: &Asset) -> ArkResult<()> {
        let metadata_json = serde_json::to_string(&asset.metadata)
            .map_err(|e| arkd_core::ArkError::Internal(format!("Metadata serialization: {e}")))?;

        let max_supply = asset.max_supply.map(|v| v as i64);

        sqlx::query(
            "INSERT OR REPLACE INTO assets (asset_id, amount, issuer_pubkey, max_supply, metadata)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&asset.asset_id)
        .bind(asset.amount as i64)
        .bind(&asset.issuer_pubkey)
        .bind(max_supply)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| arkd_core::ArkError::Internal(format!("Store asset: {e}")))?;

        Ok(())
    }

    async fn get_asset(&self, asset_id: &str) -> ArkResult<Option<Asset>> {
        let row = sqlx::query_as::<_, (String, i64, String, Option<i64>, String)>(
            "SELECT asset_id, amount, issuer_pubkey, max_supply, metadata FROM assets WHERE asset_id = ?"
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| arkd_core::ArkError::Internal(format!("Get asset: {e}")))?;

        match row {
            Some((id, amount, issuer, max_supply, meta_json)) => {
                let metadata: HashMap<String, String> =
                    serde_json::from_str(&meta_json).unwrap_or_default();
                Ok(Some(Asset {
                    asset_id: id,
                    amount: amount as u64,
                    issuer_pubkey: issuer,
                    max_supply: max_supply.map(|v| v as u64),
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_assets(&self) -> ArkResult<Vec<Asset>> {
        let rows = sqlx::query_as::<_, (String, i64, String, Option<i64>, String)>(
            "SELECT asset_id, amount, issuer_pubkey, max_supply, metadata FROM assets ORDER BY asset_id"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| arkd_core::ArkError::Internal(format!("List assets: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|(id, amount, issuer, max_supply, meta_json)| {
                let metadata: HashMap<String, String> =
                    serde_json::from_str(&meta_json).unwrap_or_default();
                Asset {
                    asset_id: id,
                    amount: amount as u64,
                    issuer_pubkey: issuer,
                    max_supply: max_supply.map(|v| v as u64),
                    metadata,
                }
            })
            .collect())
    }

    async fn store_issuance(&self, issuance: &AssetIssuance) -> ArkResult<()> {
        let metadata_json = serde_json::to_string(&issuance.metadata)
            .map_err(|e| arkd_core::ArkError::Internal(format!("Metadata serialization: {e}")))?;

        sqlx::query(
            "INSERT OR REPLACE INTO asset_issuances (txid, asset_id, amount, issuer_pubkey, control_asset_id, metadata)
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&issuance.txid)
        .bind(&issuance.asset_id)
        .bind(issuance.amount as i64)
        .bind(&issuance.issuer_pubkey)
        .bind(&issuance.control_asset_id)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await
        .map_err(|e| arkd_core::ArkError::Internal(format!("Store issuance: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = SqliteAssetRepository::new(pool.clone());
        repo.run_migration().await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_store_and_get_asset() {
        let pool = test_pool().await;
        let repo = SqliteAssetRepository::new(pool);

        let asset = Asset {
            asset_id: "test123".to_string(),
            amount: 1_000_000,
            issuer_pubkey: "02abcdef".to_string(),
            max_supply: Some(21_000_000),
            metadata: HashMap::from([("name".to_string(), "TestCoin".to_string())]),
        };

        repo.store_asset(&asset).await.unwrap();
        let retrieved = repo.get_asset("test123").await.unwrap().unwrap();
        assert_eq!(retrieved.asset_id, "test123");
        assert_eq!(retrieved.amount, 1_000_000);
        assert_eq!(retrieved.max_supply, Some(21_000_000));
        assert_eq!(retrieved.metadata.get("name").unwrap(), "TestCoin");
    }

    #[tokio::test]
    async fn test_get_nonexistent_asset() {
        let pool = test_pool().await;
        let repo = SqliteAssetRepository::new(pool);
        let result = repo.get_asset("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_assets() {
        let pool = test_pool().await;
        let repo = SqliteAssetRepository::new(pool);

        for i in 0..3 {
            repo.store_asset(&Asset {
                asset_id: format!("asset_{i}"),
                amount: (i + 1) as u64 * 1000,
                issuer_pubkey: "pk".to_string(),
                max_supply: None,
                metadata: HashMap::new(),
            })
            .await
            .unwrap();
        }

        let assets = repo.list_assets().await.unwrap();
        assert_eq!(assets.len(), 3);
    }

    #[tokio::test]
    async fn test_store_issuance() {
        let pool = test_pool().await;
        let repo = SqliteAssetRepository::new(pool);

        // Store the asset first
        repo.store_asset(&Asset {
            asset_id: "asset_1".to_string(),
            amount: 1000,
            issuer_pubkey: "pk".to_string(),
            max_supply: None,
            metadata: HashMap::new(),
        })
        .await
        .unwrap();

        let issuance = AssetIssuance {
            txid: "tx_1".to_string(),
            asset_id: "asset_1".to_string(),
            amount: 500,
            issuer_pubkey: "pk".to_string(),
            control_asset_id: None,
            metadata: HashMap::new(),
        };

        repo.store_issuance(&issuance).await.unwrap();
    }
}
