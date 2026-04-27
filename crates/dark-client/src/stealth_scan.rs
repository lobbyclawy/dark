//! Background stealth scanning loop for `dark-client`.
//!
//! `StealthScanner` is a long-running task that polls the operator's
//! `GetRoundAnnouncements` stream for new stealth announcements, scans each
//! one against the recipient's view key, and persists discovered VTXOs into
//! the local [`InMemoryStore`].
//!
//! ## Lifecycle
//!
//! The scanner is constructed with the recipient's keys, an
//! [`AnnouncementSource`], a local [`InMemoryStore`], and a
//! [`tokio_util::sync::CancellationToken`] for shutdown. Calling
//! [`StealthScanner::start`] consumes it and spawns a tokio task that loops
//! until cancellation:
//!
//! 1. Fetch the next page of announcements (resuming from the persisted
//!    checkpoint).
//! 2. Scan each announcement; persist matches.
//! 3. Persist the new checkpoint.
//! 4. Sleep `poll_interval` (interruptible by the cancellation token).
//!
//! On startup the checkpoint is hydrated from the store's metadata under
//! [`CHECKPOINT_METADATA_KEY`]; if absent the scanner starts from genesis.
//!
//! ## Stubbed dependencies
//!
//! - **#555** — recipient-side scan logic. [`scan_announcement`] is currently
//!   a placeholder that matches when an announcement's `ephemeral_pubkey`
//!   equals the hex-encoded compressed `spend_pk`. This is sufficient to
//!   exercise the loop end-to-end; the real ECDH-based check will replace
//!   it.
//! - **#557** — the typed gRPC `GetRoundAnnouncements` client already
//!   exists on [`ArkClient::get_round_announcements`]. We wrap it behind the
//!   [`AnnouncementSource`] trait so tests can substitute a fake source
//!   without spinning up a full gRPC server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::client::ArkClient;
use crate::error::ClientResult;
use crate::store::InMemoryStore;
use crate::types::{RoundAnnouncement, Vtxo};

/// Default poll interval for the scanner loop.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Default page size when fetching announcements.
pub const DEFAULT_PAGE_LIMIT: u32 = 1_000;

/// Metadata key under which the scanner persists its resume cursor.
pub const CHECKPOINT_METADATA_KEY: &str = "stealth_scan:checkpoint";

/// Resume cursor for the announcement stream.
///
/// `(round_id, vtxo_id)` is treated as exclusive — the next fetch will start
/// strictly after this pair, mirroring the server's cursor semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScannerCheckpoint {
    pub round_id: String,
    pub vtxo_id: String,
}

impl ScannerCheckpoint {
    /// True for the genesis (empty) checkpoint — i.e. nothing scanned yet.
    pub fn is_genesis(&self) -> bool {
        self.round_id.is_empty() && self.vtxo_id.is_empty()
    }

    /// Encode as `<round_id>\n<vtxo_id>` — the format consumed by the
    /// `GetRoundAnnouncements` `cursor` field.
    pub fn encode(&self) -> String {
        format!("{}\n{}", self.round_id, self.vtxo_id)
    }

    /// Decode a serialized checkpoint produced by [`Self::encode`].
    pub fn decode(raw: &str) -> Option<Self> {
        let (round_id, vtxo_id) = raw.split_once('\n')?;
        Some(Self {
            round_id: round_id.to_string(),
            vtxo_id: vtxo_id.to_string(),
        })
    }
}

/// Result of a successful announcement scan.
///
/// TODO(#555): expand to carry the shared secret and one-time spend key
/// derivation material once the real recipient-scan logic lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealthMatch {
    pub vtxo_id: String,
    pub round_id: String,
}

/// Scan a single announcement against the recipient's keys.
///
/// TODO(#555): replace this stub with the real `ECDH(scan_priv, ephemeral_pk)`
/// derivation and constant-time compare against the announced one-time key.
/// For now the announcement matches when its `ephemeral_pubkey` equals the
/// hex-encoded compressed serialization of `spend_pk` — a placeholder that
/// lets the scanner loop be exercised end-to-end.
pub fn scan_announcement(
    _scan_priv: &SecretKey,
    spend_pk: &PublicKey,
    announcement: &RoundAnnouncement,
) -> Option<StealthMatch> {
    let expected = hex::encode(spend_pk.serialize());
    if announcement.ephemeral_pubkey == expected {
        Some(StealthMatch {
            vtxo_id: announcement.vtxo_id.clone(),
            round_id: announcement.round_id.clone(),
        })
    } else {
        None
    }
}

/// Source of round announcements — abstracted so tests can supply a fake
/// without depending on a running gRPC server.
#[async_trait]
pub trait AnnouncementSource: Send + Sync {
    /// Fetch the next page of announcements after `cursor` (exclusive). When
    /// `cursor.is_genesis()`, the implementation may return the very first
    /// page from the server's view of history.
    async fn fetch(
        &self,
        cursor: &ScannerCheckpoint,
        limit: u32,
    ) -> ClientResult<Vec<RoundAnnouncement>>;

    /// Fetch the full VTXO for a matched announcement so the scanner can
    /// persist it locally.
    ///
    /// TODO(#558): the real implementation will fetch the VTXO over gRPC,
    /// decrypt the memo, and store the opening alongside `(amount, blinding,
    /// one_time_sk)`. The default impl returns `None`, leaving it up to the
    /// caller (or a richer source) to materialize VTXO bodies.
    async fn fetch_vtxo(&self, _matched: &StealthMatch) -> ClientResult<Option<Vtxo>> {
        Ok(None)
    }
}

/// [`AnnouncementSource`] backed by a shared [`ArkClient`].
pub struct ArkClientSource {
    client: Arc<Mutex<ArkClient>>,
}

impl ArkClientSource {
    pub fn new(client: Arc<Mutex<ArkClient>>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AnnouncementSource for ArkClientSource {
    async fn fetch(
        &self,
        cursor: &ScannerCheckpoint,
        limit: u32,
    ) -> ClientResult<Vec<RoundAnnouncement>> {
        let mut client = self.client.lock().await;
        // The server requires either a cursor or both round_id_start and
        // round_id_end. From genesis we use a wide-open range; otherwise we
        // resume from the encoded cursor.
        if cursor.is_genesis() {
            client
                .get_round_announcements(Some(""), Some("\u{10FFFF}"), None, Some(limit))
                .await
        } else {
            let encoded = cursor.encode();
            client
                .get_round_announcements(None, None, Some(&encoded), Some(limit))
                .await
        }
    }
}

/// Atomic counters exposed for observability — scan rate and match count
/// can be sampled cheaply from any thread. The string `round_id` of the
/// most recently scanned announcement lives on [`StealthScanner::checkpoint`].
#[derive(Debug, Default)]
pub struct ScannerMetrics {
    /// Total announcements processed since startup.
    pub announcements_scanned: AtomicU64,
    /// Total announcements that produced a `StealthMatch`.
    pub matches_found: AtomicU64,
    /// Number of poll iterations completed.
    pub poll_iterations: AtomicU64,
    /// Number of polls that failed with a transient error.
    pub poll_errors: AtomicU64,
    /// Number of non-empty pages observed — useful as a rough scan-rate
    /// signal independent of `poll_iterations`.
    pub pages_with_data: AtomicU64,
}

impl ScannerMetrics {
    pub fn announcements_scanned(&self) -> u64 {
        self.announcements_scanned.load(Ordering::Relaxed)
    }
    pub fn matches_found(&self) -> u64 {
        self.matches_found.load(Ordering::Relaxed)
    }
    pub fn poll_iterations(&self) -> u64 {
        self.poll_iterations.load(Ordering::Relaxed)
    }
    pub fn poll_errors(&self) -> u64 {
        self.poll_errors.load(Ordering::Relaxed)
    }
    pub fn pages_with_data(&self) -> u64 {
        self.pages_with_data.load(Ordering::Relaxed)
    }
}

/// Configuration for [`StealthScanner`].
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub poll_interval: Duration,
    pub page_limit: u32,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            page_limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

/// Long-running stealth scanner — see module docs for the lifecycle.
pub struct StealthScanner {
    scan_priv: SecretKey,
    spend_pk: PublicKey,
    source: Arc<dyn AnnouncementSource>,
    store: InMemoryStore,
    config: ScannerConfig,
    cancel: CancellationToken,
    metrics: Arc<ScannerMetrics>,
    checkpoint: Arc<Mutex<ScannerCheckpoint>>,
}

impl StealthScanner {
    pub fn new(
        scan_priv: SecretKey,
        spend_pk: PublicKey,
        source: Arc<dyn AnnouncementSource>,
        store: InMemoryStore,
    ) -> Self {
        Self::with_config(scan_priv, spend_pk, source, store, ScannerConfig::default())
    }

    pub fn with_config(
        scan_priv: SecretKey,
        spend_pk: PublicKey,
        source: Arc<dyn AnnouncementSource>,
        store: InMemoryStore,
        config: ScannerConfig,
    ) -> Self {
        let checkpoint = hydrate_checkpoint(&store);
        Self {
            scan_priv,
            spend_pk,
            source,
            store,
            config,
            cancel: CancellationToken::new(),
            metrics: Arc::new(ScannerMetrics::default()),
            checkpoint: Arc::new(Mutex::new(checkpoint)),
        }
    }

    /// Replace the default cancellation token. Useful when callers want to
    /// drive multiple background tasks from a single shared token.
    pub fn with_cancellation(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Handle to the cancellation token — call `.cancel()` to request a
    /// graceful shutdown.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Cloneable handle to the scanner's metrics counters.
    pub fn metrics(&self) -> Arc<ScannerMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Snapshot of the current resume cursor.
    pub async fn checkpoint(&self) -> ScannerCheckpoint {
        self.checkpoint.lock().await.clone()
    }

    /// Spawn the scanning loop on the current tokio runtime.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(self.run())
    }

    /// Drive the loop on the current task. Returns when cancellation fires.
    pub async fn run(self) {
        info!(
            poll_interval_ms = self.config.poll_interval.as_millis() as u64,
            "Stealth scanner started"
        );
        loop {
            self.poll_once().await;
            self.metrics.poll_iterations.fetch_add(1, Ordering::Relaxed);

            tokio::select! {
                _ = self.cancel.cancelled() => {
                    info!("Stealth scanner shutting down");
                    return;
                }
                _ = time::sleep(self.config.poll_interval) => {}
            }
        }
    }

    async fn poll_once(&self) {
        let cursor = self.checkpoint.lock().await.clone();
        let announcements = match self.source.fetch(&cursor, self.config.page_limit).await {
            Ok(a) => a,
            Err(err) => {
                warn!(%err, "Stealth scanner: announcement fetch failed");
                self.metrics.poll_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        if announcements.is_empty() {
            debug!("Stealth scanner: no new announcements");
            return;
        }

        let outcome = scan_page(&self.scan_priv, &self.spend_pk, &announcements, &cursor);
        self.metrics
            .announcements_scanned
            .fetch_add(outcome.scanned, Ordering::Relaxed);

        for matched in &outcome.matches {
            self.persist_match(matched).await;
        }

        self.metrics
            .matches_found
            .fetch_add(outcome.matches.len() as u64, Ordering::Relaxed);
        self.metrics.pages_with_data.fetch_add(1, Ordering::Relaxed);

        self.advance_checkpoint(outcome.last_seen).await;

        debug!(
            scanned = outcome.scanned,
            matched = outcome.matches.len(),
            "Stealth scanner: poll complete"
        );
    }

    async fn persist_match(&self, matched: &StealthMatch) {
        match self.source.fetch_vtxo(matched).await {
            Ok(Some(vtxo)) => self.store.upsert_vtxo(vtxo),
            Ok(None) => {
                // TODO(#558): once `fetch_vtxo` is wired to the operator,
                // remove this fallback. For now we record a placeholder so
                // tests can verify the persist path.
                self.store.upsert_vtxo(placeholder_vtxo(matched));
            }
            Err(err) => warn!(
                %err,
                vtxo_id = %matched.vtxo_id,
                "Stealth scanner: VTXO fetch failed"
            ),
        }
    }

    async fn advance_checkpoint(&self, new_cursor: ScannerCheckpoint) {
        {
            let mut current = self.checkpoint.lock().await;
            *current = new_cursor.clone();
        }
        self.store
            .set_metadata(CHECKPOINT_METADATA_KEY, new_cursor.encode());
    }
}

/// Result of scanning a single page of announcements.
///
/// Carries everything callers need to update metrics, persist matches,
/// and advance the cursor — exposed so both the long-running scanner
/// loop and the one-shot restore flow share a single processing rule.
#[derive(Debug, Default, Clone)]
pub struct PageScanOutcome {
    /// Number of announcements processed (== `announcements.len()`).
    pub scanned: u64,
    /// Matches found in the page, in input order.
    pub matches: Vec<StealthMatch>,
    /// Cursor of the last announcement seen — the next page MUST be
    /// fetched strictly after this.
    pub last_seen: ScannerCheckpoint,
}

/// Scan one page of announcements against the recipient's keys.
///
/// `previous_cursor` is the cursor that produced this page; it is used
/// as `last_seen` when the page is empty so callers can keep advancing
/// past stretches with no announcements without losing their place.
pub fn scan_page(
    scan_priv: &SecretKey,
    spend_pk: &PublicKey,
    announcements: &[RoundAnnouncement],
    previous_cursor: &ScannerCheckpoint,
) -> PageScanOutcome {
    let mut outcome = PageScanOutcome {
        scanned: announcements.len() as u64,
        matches: Vec::new(),
        last_seen: previous_cursor.clone(),
    };

    for announcement in announcements {
        if let Some(matched) = scan_announcement(scan_priv, spend_pk, announcement) {
            outcome.matches.push(matched);
        }
        outcome.last_seen = ScannerCheckpoint {
            round_id: announcement.round_id.clone(),
            vtxo_id: announcement.vtxo_id.clone(),
        };
    }

    outcome
}

fn hydrate_checkpoint(store: &InMemoryStore) -> ScannerCheckpoint {
    store
        .get_metadata(CHECKPOINT_METADATA_KEY)
        .and_then(|raw| ScannerCheckpoint::decode(&raw))
        .unwrap_or_default()
}

/// Build a placeholder [`Vtxo`] for a stealth match while the full-fetch path
/// (#558) is still stubbed. Carries only the IDs needed to verify scanner
/// persistence in tests.
fn placeholder_vtxo(matched: &StealthMatch) -> Vtxo {
    let (txid, vout) = parse_vtxo_id(&matched.vtxo_id).unwrap_or((matched.vtxo_id.clone(), 0));
    Vtxo {
        id: matched.vtxo_id.clone(),
        txid,
        vout,
        amount: 0,
        script: String::new(),
        created_at: 0,
        expires_at: 0,
        is_spent: false,
        is_swept: false,
        is_unrolled: false,
        spent_by: String::new(),
        ark_txid: matched.round_id.clone(),
        assets: Vec::new(),
    }
}

fn parse_vtxo_id(id: &str) -> Option<(String, u32)> {
    let (txid, vout) = id.rsplit_once(':')?;
    Some((txid.to_string(), vout.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use tokio::sync::Mutex as TokioMutex;

    /// In-memory fake announcement source backed by a list mutated between
    /// polls. Lets tests script the scanner's view of the world.
    #[derive(Default)]
    struct FakeSource {
        pages: TokioMutex<Vec<Vec<RoundAnnouncement>>>,
        fetch_calls: AtomicU64,
    }

    impl FakeSource {
        fn with_pages(pages: Vec<Vec<RoundAnnouncement>>) -> Self {
            Self {
                pages: TokioMutex::new(pages),
                fetch_calls: AtomicU64::new(0),
            }
        }

        fn calls(&self) -> u64 {
            self.fetch_calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl AnnouncementSource for FakeSource {
        async fn fetch(
            &self,
            _cursor: &ScannerCheckpoint,
            _limit: u32,
        ) -> ClientResult<Vec<RoundAnnouncement>> {
            self.fetch_calls.fetch_add(1, Ordering::Relaxed);
            let mut pages = self.pages.lock().await;
            if pages.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(pages.remove(0))
            }
        }
    }

    fn make_keys() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let scan_priv = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let spend_priv = SecretKey::from_slice(&[11u8; 32]).unwrap();
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_priv);
        (scan_priv, spend_pk)
    }

    fn announcement(round_id: &str, vtxo_id: &str, ephemeral_pubkey: &str) -> RoundAnnouncement {
        RoundAnnouncement {
            cursor: format!("{round_id}\n{vtxo_id}"),
            round_id: round_id.into(),
            vtxo_id: vtxo_id.into(),
            ephemeral_pubkey: ephemeral_pubkey.into(),
        }
    }

    #[test]
    fn checkpoint_roundtrips_through_encode_decode() {
        let cp = ScannerCheckpoint {
            round_id: "round-001".into(),
            vtxo_id: "txa:0".into(),
        };
        let decoded = ScannerCheckpoint::decode(&cp.encode()).unwrap();
        assert_eq!(cp, decoded);
    }

    #[test]
    fn scan_announcement_matches_when_ephemeral_equals_spend_pk_hex() {
        let (scan_priv, spend_pk) = make_keys();
        let pk_hex = hex::encode(spend_pk.serialize());

        let hit = announcement("round-001", "tx:0", &pk_hex);
        let miss = announcement("round-001", "tx:1", "deadbeef");

        let m = scan_announcement(&scan_priv, &spend_pk, &hit).unwrap();
        assert_eq!(m.vtxo_id, "tx:0");
        assert_eq!(m.round_id, "round-001");
        assert!(scan_announcement(&scan_priv, &spend_pk, &miss).is_none());
    }

    #[tokio::test]
    async fn scanner_discovers_matching_vtxo_and_persists_it() {
        let (scan_priv, spend_pk) = make_keys();
        let pk_hex = hex::encode(spend_pk.serialize());

        let source = Arc::new(FakeSource::with_pages(vec![
            vec![
                announcement("round-001", "tx:0", "decoy"),
                announcement("round-001", "tx:1", &pk_hex),
            ],
            // Subsequent polls return nothing — the scanner sits idle.
            vec![],
        ]));
        let store = InMemoryStore::new();

        let scanner = StealthScanner::with_config(
            scan_priv,
            spend_pk,
            source.clone(),
            store.clone(),
            ScannerConfig {
                poll_interval: Duration::from_millis(10),
                page_limit: 100,
            },
        );
        let metrics = scanner.metrics();
        let cancel = scanner.cancellation_token();
        let handle = scanner.start();

        // Wait until the scanner has consumed the scripted page.
        for _ in 0..200 {
            if metrics.matches_found() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        cancel.cancel();
        handle.await.expect("scanner task panicked");

        assert_eq!(metrics.matches_found(), 1);
        assert_eq!(metrics.announcements_scanned(), 2);
        assert!(source.calls() >= 1);
        assert!(store.get_vtxo("tx:1").is_some(), "match must be persisted");
    }

    #[tokio::test]
    async fn scanner_resumes_from_persisted_checkpoint_after_restart() {
        let (scan_priv, spend_pk) = make_keys();

        // Pre-seed the checkpoint as if a previous run had completed.
        let store = InMemoryStore::new();
        let prior = ScannerCheckpoint {
            round_id: "round-007".into(),
            vtxo_id: "tx:42".into(),
        };
        store.set_metadata(CHECKPOINT_METADATA_KEY, prior.encode());

        let source = Arc::new(FakeSource::default());
        let scanner = StealthScanner::new(scan_priv, spend_pk, source, store);

        assert_eq!(scanner.checkpoint().await, prior);
    }

    #[tokio::test]
    async fn scanner_advances_checkpoint_to_last_seen_announcement() {
        let (scan_priv, spend_pk) = make_keys();
        let store = InMemoryStore::new();
        let source = Arc::new(FakeSource::with_pages(vec![vec![
            announcement("round-001", "tx:0", "decoy-a"),
            announcement("round-002", "tx:9", "decoy-b"),
        ]]));

        let scanner = StealthScanner::with_config(
            scan_priv,
            spend_pk,
            source,
            store.clone(),
            ScannerConfig {
                poll_interval: Duration::from_millis(10),
                page_limit: 100,
            },
        );
        let metrics = scanner.metrics();
        let cancel = scanner.cancellation_token();
        let checkpoint_handle = Arc::clone(&scanner.checkpoint);
        let handle = scanner.start();

        for _ in 0..200 {
            if metrics.announcements_scanned() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        cancel.cancel();
        handle.await.expect("scanner task panicked");

        let final_cp = checkpoint_handle.lock().await.clone();
        assert_eq!(final_cp.round_id, "round-002");
        assert_eq!(final_cp.vtxo_id, "tx:9");
        assert_eq!(
            store.get_metadata(CHECKPOINT_METADATA_KEY).unwrap(),
            final_cp.encode()
        );
    }

    #[tokio::test]
    async fn scanner_shuts_down_promptly_on_cancellation() {
        let (scan_priv, spend_pk) = make_keys();
        let source = Arc::new(FakeSource::default());
        let scanner = StealthScanner::with_config(
            scan_priv,
            spend_pk,
            source,
            InMemoryStore::new(),
            ScannerConfig {
                // Long interval — if cancellation isn't honoured the test
                // hangs on the join.
                poll_interval: Duration::from_secs(60),
                page_limit: 100,
            },
        );

        let cancel = scanner.cancellation_token();
        let handle = scanner.start();

        // Give the loop one tick to enter sleep, then cancel.
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();

        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("scanner did not shut down within 2s")
            .expect("scanner task panicked");
    }
}
