//! In-memory implementations of live-store traits for dev/test.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use arkd_core::domain::Intent;
use arkd_core::error::ArkResult;
use arkd_core::ports::{
    ConfirmationStore, CurrentRoundStore, ForfeitTxsStore, IntentsQueue, LiveStore,
    SigningSessionStore,
};
use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// Original low-level InMemoryLiveStore (KV-based)
// ---------------------------------------------------------------------------

/// In-memory ephemeral live-store.
///
/// TTL is ignored — entries persist until explicitly deleted or the process exits.
/// Suitable for development and testing only.
#[derive(Debug, Clone, Default)]
pub struct InMemoryLiveStore {
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryLiveStore {
    /// Create a new empty in-memory live-store.
    pub fn new() -> Self {
        Self::default()
    }

    fn intent_key(round_id: &str, intent_id: &str) -> String {
        format!("intents:{round_id}:{intent_id}")
    }

    fn nonce_key(session_id: &str, pubkey: &str) -> String {
        format!("nonces:{session_id}:{pubkey}")
    }

    fn partial_sig_key(session_id: &str, pubkey: &str) -> String {
        format!("partial_sigs:{session_id}:{pubkey}")
    }
}

#[async_trait]
impl LiveStore for InMemoryLiveStore {
    async fn set_intent(
        &self,
        round_id: &str,
        intent_id: &str,
        data: &[u8],
        _ttl_secs: u64,
    ) -> ArkResult<()> {
        let key = Self::intent_key(round_id, intent_id);
        self.data.write().await.insert(key, data.to_vec());
        Ok(())
    }

    async fn get_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::intent_key(round_id, intent_id);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_intents(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("intents:{round_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }

    async fn delete_intent(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        let key = Self::intent_key(round_id, intent_id);
        self.data.write().await.remove(&key);
        Ok(())
    }

    async fn set_nonce(
        &self,
        session_id: &str,
        pubkey: &str,
        nonce: &[u8],
        _ttl_secs: u64,
    ) -> ArkResult<()> {
        let key = Self::nonce_key(session_id, pubkey);
        self.data.write().await.insert(key, nonce.to_vec());
        Ok(())
    }

    async fn get_nonce(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::nonce_key(session_id, pubkey);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_nonces(&self, session_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("nonces:{session_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }

    async fn set_partial_sig(
        &self,
        session_id: &str,
        pubkey: &str,
        sig: &[u8],
        _ttl_secs: u64,
    ) -> ArkResult<()> {
        let key = Self::partial_sig_key(session_id, pubkey);
        self.data.write().await.insert(key, sig.to_vec());
        Ok(())
    }

    async fn get_partial_sig(&self, session_id: &str, pubkey: &str) -> ArkResult<Option<Vec<u8>>> {
        let key = Self::partial_sig_key(session_id, pubkey);
        Ok(self.data.read().await.get(&key).cloned())
    }

    async fn list_partial_sigs(&self, session_id: &str) -> ArkResult<Vec<String>> {
        let prefix = format!("partial_sigs:{session_id}:");
        let guard = self.data.read().await;
        let ids: Vec<String> = guard
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(ids)
    }
}

// ---------------------------------------------------------------------------
// Higher-level components
// ---------------------------------------------------------------------------

/// In-memory FIFO queue of intents.
#[derive(Debug, Default)]
pub struct InMemoryIntentsQueue(Mutex<VecDeque<Intent>>);

impl InMemoryIntentsQueue {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IntentsQueue for InMemoryIntentsQueue {
    async fn push(&self, intent: Intent) -> ArkResult<()> {
        self.0.lock().await.push_back(intent);
        Ok(())
    }

    async fn pop_all(&self) -> ArkResult<Vec<Intent>> {
        let mut q = self.0.lock().await;
        let items: Vec<Intent> = q.drain(..).collect();
        Ok(items)
    }

    async fn len(&self) -> ArkResult<usize> {
        Ok(self.0.lock().await.len())
    }

    async fn is_empty(&self) -> ArkResult<bool> {
        Ok(self.0.lock().await.is_empty())
    }

    async fn clear(&self) -> ArkResult<()> {
        self.0.lock().await.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------

/// Tracks expected vs received forfeit txs per round.
#[derive(Debug, Default)]
struct ForfeitRoundState {
    expected: usize,
    txs: Vec<String>,
}

/// In-memory forfeit transaction store.
#[derive(Debug, Default)]
pub struct InMemoryForfeitTxsStore {
    rounds: Mutex<HashMap<String, ForfeitRoundState>>,
}

impl InMemoryForfeitTxsStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ForfeitTxsStore for InMemoryForfeitTxsStore {
    async fn init(&self, round_id: &str, expected: usize) -> ArkResult<()> {
        self.rounds.lock().await.insert(
            round_id.to_string(),
            ForfeitRoundState {
                expected,
                txs: Vec::new(),
            },
        );
        Ok(())
    }

    async fn add(&self, round_id: &str, tx_hex: String) -> ArkResult<()> {
        let mut rounds = self.rounds.lock().await;
        let state = rounds
            .entry(round_id.to_string())
            .or_insert_with(|| ForfeitRoundState {
                expected: 0,
                txs: Vec::new(),
            });
        state.txs.push(tx_hex);
        Ok(())
    }

    async fn all_received(&self, round_id: &str) -> ArkResult<bool> {
        let rounds = self.rounds.lock().await;
        match rounds.get(round_id) {
            Some(state) => Ok(state.expected > 0 && state.txs.len() >= state.expected),
            None => Ok(false),
        }
    }

    async fn pop_all(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let mut rounds = self.rounds.lock().await;
        match rounds.remove(round_id) {
            Some(state) => Ok(state.txs),
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------

/// Tracks intent confirmations per round.
#[derive(Debug, Default)]
struct ConfirmationRoundState {
    expected: HashSet<String>,
    confirmed: HashSet<String>,
}

/// In-memory confirmation store.
#[derive(Debug, Default)]
pub struct InMemoryConfirmationStore {
    rounds: Mutex<HashMap<String, ConfirmationRoundState>>,
}

impl InMemoryConfirmationStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ConfirmationStore for InMemoryConfirmationStore {
    async fn init(&self, round_id: &str, intent_ids: Vec<String>) -> ArkResult<()> {
        let expected: HashSet<String> = intent_ids.into_iter().collect();
        self.rounds.lock().await.insert(
            round_id.to_string(),
            ConfirmationRoundState {
                expected,
                confirmed: HashSet::new(),
            },
        );
        Ok(())
    }

    async fn confirm(&self, round_id: &str, intent_id: &str) -> ArkResult<()> {
        let mut rounds = self.rounds.lock().await;
        if let Some(state) = rounds.get_mut(round_id) {
            state.confirmed.insert(intent_id.to_string());
        }
        Ok(())
    }

    async fn all_confirmed(&self, round_id: &str) -> ArkResult<bool> {
        let rounds = self.rounds.lock().await;
        match rounds.get(round_id) {
            Some(state) => {
                Ok(!state.expected.is_empty() && state.expected.is_subset(&state.confirmed))
            }
            None => Ok(false),
        }
    }

    async fn get_confirmed(&self, round_id: &str) -> ArkResult<Vec<String>> {
        let rounds = self.rounds.lock().await;
        match rounds.get(round_id) {
            Some(state) => Ok(state.confirmed.iter().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------

/// Per-session signing state.
#[derive(Debug, Default)]
struct SigningSession {
    participant_count: usize,
    nonces: HashMap<String, Vec<u8>>,
    signatures: HashMap<String, Vec<u8>>,
}

/// In-memory MuSig2 signing session store.
#[derive(Debug, Default)]
pub struct InMemorySigningSessionStore {
    sessions: Mutex<HashMap<String, SigningSession>>,
}

impl InMemorySigningSessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SigningSessionStore for InMemorySigningSessionStore {
    async fn init_session(&self, session_id: &str, participant_count: usize) -> ArkResult<()> {
        self.sessions.lock().await.insert(
            session_id.to_string(),
            SigningSession {
                participant_count,
                nonces: HashMap::new(),
                signatures: HashMap::new(),
            },
        );
        Ok(())
    }

    async fn add_nonce(
        &self,
        session_id: &str,
        participant_id: &str,
        nonce: Vec<u8>,
    ) -> ArkResult<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.nonces.insert(participant_id.to_string(), nonce);
        }
        Ok(())
    }

    async fn all_nonces_collected(&self, session_id: &str) -> ArkResult<bool> {
        let sessions = self.sessions.lock().await;
        match sessions.get(session_id) {
            Some(s) => Ok(s.nonces.len() >= s.participant_count),
            None => Ok(false),
        }
    }

    async fn add_signature(
        &self,
        session_id: &str,
        participant_id: &str,
        sig: Vec<u8>,
    ) -> ArkResult<()> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.signatures.insert(participant_id.to_string(), sig);
        }
        Ok(())
    }

    async fn all_signatures_collected(&self, session_id: &str) -> ArkResult<bool> {
        let sessions = self.sessions.lock().await;
        match sessions.get(session_id) {
            Some(s) => Ok(s.signatures.len() >= s.participant_count),
            None => Ok(false),
        }
    }

    async fn get_nonces(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        let sessions = self.sessions.lock().await;
        match sessions.get(session_id) {
            Some(s) => Ok(s.nonces.values().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }

    async fn get_signatures(&self, session_id: &str) -> ArkResult<Vec<Vec<u8>>> {
        let sessions = self.sessions.lock().await;
        match sessions.get(session_id) {
            Some(s) => Ok(s.signatures.values().cloned().collect()),
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------

/// In-memory current round store.
#[derive(Debug, Default)]
pub struct InMemoryCurrentRoundStore(RwLock<Option<String>>);

impl InMemoryCurrentRoundStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CurrentRoundStore for InMemoryCurrentRoundStore {
    async fn get_current_round_id(&self) -> ArkResult<Option<String>> {
        Ok(self.0.read().await.clone())
    }

    async fn set_current_round_id(&self, round_id: &str) -> ArkResult<()> {
        *self.0.write().await = Some(round_id.to_string());
        Ok(())
    }

    async fn clear(&self) -> ArkResult<()> {
        *self.0.write().await = None;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unified ArkLiveStore
// ---------------------------------------------------------------------------

/// Bundles all ephemeral round-state stores into a single handle.
pub struct ArkLiveStore {
    pub intents: Arc<dyn IntentsQueue>,
    pub forfeits: Arc<dyn ForfeitTxsStore>,
    pub confirmations: Arc<dyn ConfirmationStore>,
    pub signing: Arc<dyn SigningSessionStore>,
    pub current_round: Arc<dyn CurrentRoundStore>,
}

impl ArkLiveStore {
    /// Create an `ArkLiveStore` backed entirely by in-memory implementations.
    pub fn in_memory() -> Self {
        Self {
            intents: Arc::new(InMemoryIntentsQueue::new()),
            forfeits: Arc::new(InMemoryForfeitTxsStore::new()),
            confirmations: Arc::new(InMemoryConfirmationStore::new()),
            signing: Arc::new(InMemorySigningSessionStore::new()),
            current_round: Arc::new(InMemoryCurrentRoundStore::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::domain::vtxo::{Receiver, Vtxo, VtxoOutpoint};

    fn make_test_intent(id: &str) -> Intent {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("deadbeef".to_string(), 0),
            50_000,
            "pubkey".to_string(),
        );
        let mut intent = Intent::new(
            "txid".to_string(),
            "proof".to_string(),
            "msg".to_string(),
            vec![vtxo],
        )
        .unwrap();
        // Override the auto-generated id for deterministic testing
        intent.id = id.to_string();
        intent
            .add_receivers(vec![Receiver::offchain(25_000, "pk1".to_string())])
            .unwrap();
        intent
    }

    // --- Original low-level LiveStore tests ---

    #[tokio::test]
    async fn test_memory_set_get_intent() {
        let store = InMemoryLiveStore::new();
        let data = b"test-intent-data";
        store
            .set_intent("round-1", "intent-a", data, 300)
            .await
            .unwrap();
        let got = store.get_intent("round-1", "intent-a").await.unwrap();
        assert_eq!(got, Some(data.to_vec()));
    }

    #[tokio::test]
    async fn test_memory_list_intents() {
        let store = InMemoryLiveStore::new();
        store
            .set_intent("round-1", "intent-a", b"a", 300)
            .await
            .unwrap();
        store
            .set_intent("round-1", "intent-b", b"b", 300)
            .await
            .unwrap();
        store
            .set_intent("round-2", "intent-c", b"c", 300)
            .await
            .unwrap();
        let mut ids = store.list_intents("round-1").await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["intent-a", "intent-b"]);
    }

    #[tokio::test]
    async fn test_memory_delete_intent() {
        let store = InMemoryLiveStore::new();
        store
            .set_intent("round-1", "intent-a", b"data", 300)
            .await
            .unwrap();
        store.delete_intent("round-1", "intent-a").await.unwrap();
        let got = store.get_intent("round-1", "intent-a").await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn test_memory_nonce_roundtrip() {
        let store = InMemoryLiveStore::new();
        let nonce = b"random-nonce-bytes";
        store
            .set_nonce("session-1", "pk-abc", nonce, 120)
            .await
            .unwrap();
        let got = store.get_nonce("session-1", "pk-abc").await.unwrap();
        assert_eq!(got, Some(nonce.to_vec()));
        let keys = store.list_nonces("session-1").await.unwrap();
        assert_eq!(keys, vec!["pk-abc"]);
    }

    #[tokio::test]
    async fn test_memory_partial_sig_roundtrip() {
        let store = InMemoryLiveStore::new();
        let sig = b"partial-sig-bytes";
        store
            .set_partial_sig("session-1", "pk-xyz", sig, 120)
            .await
            .unwrap();
        let got = store.get_partial_sig("session-1", "pk-xyz").await.unwrap();
        assert_eq!(got, Some(sig.to_vec()));
        let keys = store.list_partial_sigs("session-1").await.unwrap();
        assert_eq!(keys, vec!["pk-xyz"]);
    }

    #[tokio::test]
    async fn test_memory_get_nonexistent_returns_none() {
        let store = InMemoryLiveStore::new();
        assert_eq!(store.get_intent("x", "y").await.unwrap(), None);
        assert_eq!(store.get_nonce("x", "y").await.unwrap(), None);
        assert_eq!(store.get_partial_sig("x", "y").await.unwrap(), None);
    }

    // --- Higher-level component tests ---

    #[tokio::test]
    async fn test_intents_queue_push_pop() {
        let queue = InMemoryIntentsQueue::new();
        let i1 = make_test_intent("intent-1");
        let i2 = make_test_intent("intent-2");

        queue.push(i1).await.unwrap();
        queue.push(i2).await.unwrap();
        assert_eq!(queue.len().await.unwrap(), 2);

        let all = queue.pop_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "intent-1");
        assert_eq!(all[1].id, "intent-2");

        // Queue should be empty after pop_all
        assert_eq!(queue.len().await.unwrap(), 0);
        assert!(queue.pop_all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_forfeit_txs_all_received() {
        let store = InMemoryForfeitTxsStore::new();
        store.init("round-1", 2).await.unwrap();

        assert!(!store.all_received("round-1").await.unwrap());

        store.add("round-1", "tx_hex_1".to_string()).await.unwrap();
        assert!(!store.all_received("round-1").await.unwrap());

        store.add("round-1", "tx_hex_2".to_string()).await.unwrap();
        assert!(store.all_received("round-1").await.unwrap());

        let txs = store.pop_all("round-1").await.unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs, vec!["tx_hex_1", "tx_hex_2"]);

        // After pop_all, round state is removed
        assert!(store.pop_all("round-1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_confirmation_all_confirmed() {
        let store = InMemoryConfirmationStore::new();
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        store.init("round-1", ids).await.unwrap();

        assert!(!store.all_confirmed("round-1").await.unwrap());

        store.confirm("round-1", "a").await.unwrap();
        store.confirm("round-1", "b").await.unwrap();
        assert!(!store.all_confirmed("round-1").await.unwrap());

        store.confirm("round-1", "c").await.unwrap();
        assert!(store.all_confirmed("round-1").await.unwrap());

        let confirmed = store.get_confirmed("round-1").await.unwrap();
        assert_eq!(confirmed.len(), 3);
    }

    #[tokio::test]
    async fn test_signing_session_nonces_and_sigs() {
        let store = InMemorySigningSessionStore::new();
        store.init_session("sess-1", 2).await.unwrap();

        assert!(!store.all_nonces_collected("sess-1").await.unwrap());

        store
            .add_nonce("sess-1", "p1", vec![1, 2, 3])
            .await
            .unwrap();
        assert!(!store.all_nonces_collected("sess-1").await.unwrap());

        store
            .add_nonce("sess-1", "p2", vec![4, 5, 6])
            .await
            .unwrap();
        assert!(store.all_nonces_collected("sess-1").await.unwrap());

        let nonces = store.get_nonces("sess-1").await.unwrap();
        assert_eq!(nonces.len(), 2);

        // Signatures
        assert!(!store.all_signatures_collected("sess-1").await.unwrap());
        store
            .add_signature("sess-1", "p1", vec![10, 20])
            .await
            .unwrap();
        store
            .add_signature("sess-1", "p2", vec![30, 40])
            .await
            .unwrap();
        assert!(store.all_signatures_collected("sess-1").await.unwrap());

        let sigs = store.get_signatures("sess-1").await.unwrap();
        assert_eq!(sigs.len(), 2);
    }

    #[tokio::test]
    async fn test_current_round_store_get_set() {
        let store = InMemoryCurrentRoundStore::new();

        assert_eq!(store.get_current_round_id().await.unwrap(), None);

        store.set_current_round_id("round-42").await.unwrap();
        assert_eq!(
            store.get_current_round_id().await.unwrap(),
            Some("round-42".to_string())
        );

        store.clear().await.unwrap();
        assert_eq!(store.get_current_round_id().await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_ark_live_store_in_memory() {
        let live = ArkLiveStore::in_memory();

        // Smoke test: use each component
        let intent = make_test_intent("test-1");
        live.intents.push(intent).await.unwrap();
        assert_eq!(live.intents.len().await.unwrap(), 1);

        live.current_round.set_current_round_id("r1").await.unwrap();
        assert_eq!(
            live.current_round.get_current_round_id().await.unwrap(),
            Some("r1".to_string())
        );
    }
}
