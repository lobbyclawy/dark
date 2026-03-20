//! In-memory client-side state store for the Ark client SDK.
//!
//! Provides persistence for client configuration, VTXOs, and pending
//! transactions. Mirrors Go's `client-lib/store` with both in-memory
//! and (future) file-backed implementations.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::types::Vtxo;

/// Client configuration stored locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server URL (gRPC endpoint).
    pub server_url: String,
    /// Bitcoin network (mainnet, testnet, signet, regtest).
    pub network: String,
    /// Server's public key (hex).
    pub server_pubkey: String,
    /// Round session duration in seconds.
    pub session_duration: u32,
    /// Unilateral exit delay in blocks.
    pub unilateral_exit_delay: u32,
    /// Dust limit in satoshis.
    pub dust: u64,
}

/// A pending off-chain transaction awaiting confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTx {
    /// Transaction ID.
    pub tx_id: String,
    /// Amount in satoshis.
    pub amount: u64,
    /// Destination address/script.
    pub destination: String,
    /// Unix timestamp when created.
    pub created_at: i64,
    /// Current status (pending, confirmed, failed).
    pub status: String,
}

/// Thread-safe in-memory store for client state.
///
/// All methods are synchronous and use interior mutability via `RwLock`.
/// The store is `Clone`-able and `Send + Sync` for use across async tasks.
#[derive(Debug, Clone)]
pub struct InMemoryStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Debug)]
struct StoreInner {
    config: Option<ClientConfig>,
    vtxos: HashMap<String, Vtxo>,
    pending_txs: HashMap<String, PendingTx>,
    /// Arbitrary key-value metadata.
    metadata: HashMap<String, String>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                config: None,
                vtxos: HashMap::new(),
                pending_txs: HashMap::new(),
                metadata: HashMap::new(),
            })),
        }
    }

    // ── Config ─────────────────────────────────────────────────────

    /// Save the client configuration.
    pub fn set_config(&self, config: ClientConfig) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.config = Some(config);
    }

    /// Get the current client configuration, if set.
    pub fn get_config(&self) -> Option<ClientConfig> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.config.clone()
    }

    // ── VTXOs ──────────────────────────────────────────────────────

    /// Store or update a VTXO.
    pub fn upsert_vtxo(&self, vtxo: Vtxo) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.vtxos.insert(vtxo.id.clone(), vtxo);
    }

    /// Store multiple VTXOs at once (replaces existing by ID).
    pub fn upsert_vtxos(&self, vtxos: Vec<Vtxo>) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        for vtxo in vtxos {
            inner.vtxos.insert(vtxo.id.clone(), vtxo);
        }
    }

    /// Get a VTXO by ID.
    pub fn get_vtxo(&self, id: &str) -> Option<Vtxo> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.vtxos.get(id).cloned()
    }

    /// List all stored VTXOs.
    pub fn list_vtxos(&self) -> Vec<Vtxo> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.vtxos.values().cloned().collect()
    }

    /// List only spendable (not spent, not swept) VTXOs.
    pub fn list_spendable_vtxos(&self) -> Vec<Vtxo> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .vtxos
            .values()
            .filter(|v| !v.is_spent && !v.is_swept)
            .cloned()
            .collect()
    }

    /// Remove a VTXO by ID. Returns the removed VTXO if it existed.
    pub fn remove_vtxo(&self, id: &str) -> Option<Vtxo> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.vtxos.remove(id)
    }

    /// Clear all VTXOs.
    pub fn clear_vtxos(&self) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.vtxos.clear();
    }

    // ── Pending transactions ───────────────────────────────────────

    /// Add or update a pending transaction.
    pub fn upsert_pending_tx(&self, tx: PendingTx) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.pending_txs.insert(tx.tx_id.clone(), tx);
    }

    /// Get a pending transaction by ID.
    pub fn get_pending_tx(&self, tx_id: &str) -> Option<PendingTx> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.pending_txs.get(tx_id).cloned()
    }

    /// List all pending transactions.
    pub fn list_pending_txs(&self) -> Vec<PendingTx> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.pending_txs.values().cloned().collect()
    }

    /// Remove a pending transaction by ID.
    pub fn remove_pending_tx(&self, tx_id: &str) -> Option<PendingTx> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.pending_txs.remove(tx_id)
    }

    /// Clear all pending transactions.
    pub fn clear_pending_txs(&self) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.pending_txs.clear();
    }

    // ── Metadata ───────────────────────────────────────────────────

    /// Set a metadata key-value pair.
    pub fn set_metadata(&self, key: impl Into<String>, value: impl Into<String>) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.metadata.insert(key.into(), value.into());
    }

    /// Get a metadata value by key.
    pub fn get_metadata(&self, key: &str) -> Option<String> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.metadata.get(key).cloned()
    }

    /// Remove a metadata key.
    pub fn remove_metadata(&self, key: &str) -> Option<String> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.metadata.remove(key)
    }

    // ── Serialization ──────────────────────────────────────────────

    /// Export the entire store as JSON (for file-based persistence).
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let inner = self.inner.read().expect("store lock poisoned");
        let snapshot = StoreSnapshot {
            config: inner.config.clone(),
            vtxos: inner.vtxos.values().cloned().collect(),
            pending_txs: inner.pending_txs.values().cloned().collect(),
            metadata: inner.metadata.clone(),
        };
        serde_json::to_string_pretty(&snapshot)
    }

    /// Import state from a JSON string (restores a previously exported snapshot).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        let snapshot: StoreSnapshot = serde_json::from_str(json)?;
        let store = Self::new();
        {
            let mut inner = store.inner.write().expect("store lock poisoned");
            inner.config = snapshot.config;
            for vtxo in snapshot.vtxos {
                inner.vtxos.insert(vtxo.id.clone(), vtxo);
            }
            for tx in snapshot.pending_txs {
                inner.pending_txs.insert(tx.tx_id.clone(), tx);
            }
            inner.metadata = snapshot.metadata;
        }
        Ok(store)
    }
}

/// Serializable snapshot of the store for JSON export/import.
#[derive(Debug, Serialize, Deserialize)]
struct StoreSnapshot {
    config: Option<ClientConfig>,
    vtxos: Vec<Vtxo>,
    pending_txs: Vec<PendingTx>,
    metadata: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vtxo(id: &str, amount: u64) -> Vtxo {
        Vtxo {
            id: id.to_string(),
            txid: id.split(':').next().unwrap_or("tx").to_string(),
            vout: 0,
            amount,
            script: "pk".to_string(),
            created_at: 0,
            expires_at: 0,
            is_spent: false,
            is_swept: false,
            is_unrolled: false,
            spent_by: String::new(),
            ark_txid: String::new(),
            assets: vec![],
        }
    }

    #[test]
    fn test_store_config() {
        let store = InMemoryStore::new();
        assert!(store.get_config().is_none());

        store.set_config(ClientConfig {
            server_url: "http://localhost:50051".into(),
            network: "regtest".into(),
            server_pubkey: "02abc".into(),
            session_duration: 10,
            unilateral_exit_delay: 144,
            dust: 546,
        });

        let config = store.get_config().unwrap();
        assert_eq!(config.server_url, "http://localhost:50051");
        assert_eq!(config.network, "regtest");
    }

    #[test]
    fn test_store_vtxos() {
        let store = InMemoryStore::new();
        store.upsert_vtxo(make_vtxo("tx1:0", 10_000));
        store.upsert_vtxo(make_vtxo("tx2:0", 20_000));

        assert_eq!(store.list_vtxos().len(), 2);
        assert_eq!(store.get_vtxo("tx1:0").unwrap().amount, 10_000);

        store.remove_vtxo("tx1:0");
        assert_eq!(store.list_vtxos().len(), 1);
        assert!(store.get_vtxo("tx1:0").is_none());
    }

    #[test]
    fn test_store_spendable_vtxos() {
        let store = InMemoryStore::new();
        store.upsert_vtxo(make_vtxo("tx1:0", 10_000));

        let mut spent = make_vtxo("tx2:0", 20_000);
        spent.is_spent = true;
        store.upsert_vtxo(spent);

        let spendable = store.list_spendable_vtxos();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].id, "tx1:0");
    }

    #[test]
    fn test_store_pending_txs() {
        let store = InMemoryStore::new();
        store.upsert_pending_tx(PendingTx {
            tx_id: "tx1".into(),
            amount: 5000,
            destination: "bc1q...".into(),
            created_at: 1700000000,
            status: "pending".into(),
        });

        assert_eq!(store.list_pending_txs().len(), 1);
        assert_eq!(store.get_pending_tx("tx1").unwrap().amount, 5000);

        store.remove_pending_tx("tx1");
        assert!(store.get_pending_tx("tx1").is_none());
    }

    #[test]
    fn test_store_metadata() {
        let store = InMemoryStore::new();
        store.set_metadata("last_sync", "2024-01-01");
        assert_eq!(store.get_metadata("last_sync").unwrap(), "2024-01-01");

        store.remove_metadata("last_sync");
        assert!(store.get_metadata("last_sync").is_none());
    }

    #[test]
    fn test_store_json_roundtrip() {
        let store = InMemoryStore::new();
        store.set_config(ClientConfig {
            server_url: "http://localhost:50051".into(),
            network: "regtest".into(),
            server_pubkey: "02abc".into(),
            session_duration: 10,
            unilateral_exit_delay: 144,
            dust: 546,
        });
        store.upsert_vtxo(make_vtxo("tx1:0", 10_000));
        store.set_metadata("key", "value");

        let json = store.to_json().unwrap();
        let restored = InMemoryStore::from_json(&json).unwrap();

        assert_eq!(restored.get_config().unwrap().network, "regtest");
        assert_eq!(restored.list_vtxos().len(), 1);
        assert_eq!(restored.get_metadata("key").unwrap(), "value");
    }

    #[test]
    fn test_store_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryStore>();
    }
}
