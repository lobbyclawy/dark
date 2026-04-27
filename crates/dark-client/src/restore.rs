//! Wallet restore from seed with stealth VTXO re-scan (issue #560).
//!
//! Restores a wallet by deriving stealth keys from a seed and walking
//! the operator's historical round announcements to rediscover every
//! confidential VTXO paid to the wallet's `(scan_pk, spend_pk)` pair.
//!
//! ## Flow
//!
//! 1. Derive the stealth meta-address and matching secrets from the
//!    seed via [`MetaAddress::from_seed`] (issue #553).
//! 2. Initialise the scanner cursor: from the supplied `birthday_height`
//!    if present, else from a cursor previously persisted by the
//!    [`crate::stealth_scan::StealthScanner`], else from genesis.
//! 3. Drain announcements forward to the chain tip in pages, scanning
//!    each via [`crate::stealth_scan::scan_page`] and
//!    persisting any matches into the local [`InMemoryStore`].
//! 4. Persist the final cursor under
//!    [`crate::stealth_scan::CHECKPOINT_METADATA_KEY`]
//!    so the live scanner (#558) resumes from the right place after
//!    restore completes.
//!
//! ## Birthday handling
//!
//! `birthday_height: Option<u32>` is the round height the operator
//! emitted the first VTXO that may belong to this wallet. Per the
//! issue spec it lets users skip ancient rounds at the cost of missing
//! VTXOs older than the birthday. Skipping is always opt-in: a `None`
//! birthday with no prior cursor walks the full archival horizon and
//! the caller is responsible for whatever confirmation prompt their
//! UX requires (see ADR #552, "No birthday supplied").
//!
//! The height is encoded into the scanner cursor's `round_id` field
//! as a zero-padded decimal string. This is a deliberate approximation
//! pending the operator-side round-id-by-height index tracked by ADR
//! #552's open question "Birthday-as-time vs. birthday-as-round". For
//! mock-based unit tests the encoding is the contract; for production
//! gRPC the mapping will be tightened when the index lands.
//!
//! ## Errors
//!
//! ADR #552 mandates a typed `BirthdayBeforeArchivalHorizon` for the
//! case where the operator's archival horizon has advanced past the
//! requested birthday — see [`RestoreError`]. Other failure modes
//! propagate as [`RestoreError::Source`].

use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use thiserror::Error;
use tracing::{debug, info};

use dark_confidential::stealth::{MetaAddress, StealthNetwork, StealthSecrets};
use dark_confidential::ConfidentialError;

use crate::error::ClientError;
use crate::stealth_scan::{
    scan_page, AnnouncementSource, PageScanOutcome, ScannerCheckpoint, StealthMatch,
    CHECKPOINT_METADATA_KEY, DEFAULT_PAGE_LIMIT,
};
use crate::store::InMemoryStore;
use crate::types::Vtxo;

/// gRPC status text the operator returns when the requested birthday
/// is older than its archival horizon (ADR #552). Detection is
/// best-effort string matching until the gRPC client preserves
/// structured error details — see TODO in
/// [`RestoreError::from_source_error`].
const ARCHIVAL_HORIZON_MARKER: &str = "BirthdayBeforeArchivalHorizon";

/// Default cap on pages drained per restore. Bounds worst-case work
/// for a degenerate operator that streams indefinitely. At the default
/// page size this caps a single restore at 10M announcements, well
/// above ADR #552's 525_600-round archival horizon at 200 confidential
/// outputs/round.
pub const DEFAULT_RESTORE_PAGE_BUDGET: usize = 10_000;

/// Width of the zero-padded decimal cursor encoding for round heights.
/// 10 digits is enough for any plausible round count (`u32::MAX`).
const HEIGHT_CURSOR_WIDTH: usize = 10;

/// Outcome of a successful restore.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RestoreSummary {
    /// Total announcements scanned across all pages.
    pub announcements_scanned: u64,
    /// VTXOs discovered and persisted.
    pub matches_found: u64,
    /// Final cursor — the live scanner (#558) should resume here.
    pub final_cursor: ScannerCheckpoint,
    /// Number of announcement pages fetched.
    pub pages_fetched: u64,
}

/// Progress event emitted between pages so callers can render UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreProgress {
    /// Cumulative announcements scanned so far.
    pub announcements_scanned: u64,
    /// Cumulative matches persisted so far.
    pub matches_found: u64,
    /// Cumulative pages fetched so far.
    pub pages_fetched: u64,
    /// Most recent cursor — useful for "scanning at round X" displays.
    pub cursor: ScannerCheckpoint,
}

/// Callback type for streaming restore progress to a CLI or test.
pub type ProgressCallback = Arc<dyn Fn(&RestoreProgress) + Send + Sync>;

/// Errors a restore can return.
///
/// `BirthdayBeforeArchivalHorizon` carries the operator's current
/// horizon round id so the CLI can render the remediation guidance
/// described in ADR #552 ("Beyond archival horizon"). All other
/// failures propagate as [`Self::Source`] or [`Self::Derivation`].
#[derive(Debug, Error)]
pub enum RestoreError {
    /// Seed-to-meta-address derivation failed.
    #[error("stealth derivation failed: {0}")]
    Derivation(#[from] ConfidentialError),

    /// The supplied birthday is older than the operator's archival
    /// horizon. `current_horizon_round` is the operator's current
    /// horizon, suitable to suggest as the next `--birthday` value.
    #[error(
        "birthday is older than the operator's archival horizon \
         (current horizon round: {current_horizon_round})"
    )]
    BirthdayBeforeArchivalHorizon { current_horizon_round: String },

    /// The page budget was exhausted before the source returned an
    /// empty page — defensive bound, not expected on real operators.
    #[error("restore exceeded the page budget of {budget} pages")]
    PageBudgetExceeded { budget: usize },

    /// Underlying announcement source failed — network error, decode
    /// error, etc. Mapped as-is from [`ClientError`].
    #[error("announcement source error: {0}")]
    Source(#[from] ClientError),
}

impl RestoreError {
    /// Best-effort mapping from a [`ClientError`] returned by an
    /// [`AnnouncementSource`] to the typed
    /// [`Self::BirthdayBeforeArchivalHorizon`] when the underlying
    /// gRPC error carries the ADR #552 marker. Falls back to
    /// [`Self::Source`] otherwise.
    ///
    /// TODO(#552): once `dark-client::client::ArkClient` preserves
    /// structured `tonic::Status` details (`FAILED_PRECONDITION` with
    /// the typed `BirthdayBeforeArchivalHorizon` payload), match on
    /// the structured field instead of the message text.
    fn from_source_error(error: ClientError) -> Self {
        let message = error.to_string();
        if let Some(horizon) = parse_archival_horizon(&message) {
            return Self::BirthdayBeforeArchivalHorizon {
                current_horizon_round: horizon,
            };
        }
        Self::Source(error)
    }
}

/// Configuration for a restore operation.
#[derive(Clone)]
pub struct RestoreConfig {
    /// Page size requested from the source.
    pub page_limit: u32,
    /// Maximum number of pages to fetch before bailing out.
    pub page_budget: usize,
    /// Optional callback fired between pages.
    pub progress: Option<ProgressCallback>,
}

impl std::fmt::Debug for RestoreConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RestoreConfig")
            .field("page_limit", &self.page_limit)
            .field("page_budget", &self.page_budget)
            .field("progress", &self.progress.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for RestoreConfig {
    fn default() -> Self {
        Self {
            page_limit: DEFAULT_PAGE_LIMIT,
            page_budget: DEFAULT_RESTORE_PAGE_BUDGET,
            progress: None,
        }
    }
}

/// Restore a wallet from `seed` by re-scanning historical stealth
/// announcements.
///
/// Derives `(scan_pk, spend_pk)` for the given `account_index`,
/// initialises the scanner cursor (from `birthday_height`, the store's
/// existing checkpoint, or genesis), and walks the operator's
/// announcement stream to the tip — persisting every matching VTXO
/// into `store` along the way.
///
/// Returns a [`RestoreSummary`] with the final cursor; the live
/// scanner (#558) constructed against the same `store` will resume
/// from there.
pub async fn restore_from_seed(
    seed: &[u8],
    account_index: u32,
    birthday_height: Option<u32>,
    network: StealthNetwork,
    source: Arc<dyn AnnouncementSource>,
    store: InMemoryStore,
) -> Result<RestoreSummary, RestoreError> {
    restore_from_seed_with(
        seed,
        account_index,
        birthday_height,
        network,
        source,
        store,
        RestoreConfig::default(),
    )
    .await
}

/// [`restore_from_seed`] with a custom [`RestoreConfig`] — page size,
/// budget, and progress callback.
pub async fn restore_from_seed_with(
    seed: &[u8],
    account_index: u32,
    birthday_height: Option<u32>,
    network: StealthNetwork,
    source: Arc<dyn AnnouncementSource>,
    store: InMemoryStore,
    config: RestoreConfig,
) -> Result<RestoreSummary, RestoreError> {
    let (meta, secrets) = MetaAddress::from_seed(seed, account_index, network)?;
    let starting_cursor = initial_cursor(&store, birthday_height);

    info!(
        scan_pk = %hex::encode(meta.scan_pk().serialize()),
        spend_pk = %hex::encode(meta.spend_pk().serialize()),
        starting_round = %starting_cursor.round_id,
        birthday_height = ?birthday_height,
        "Wallet restore: starting stealth re-scan"
    );

    let context = RestoreContext {
        scan_pk: meta.scan_pk().serialize(),
        spend_pk: *meta.spend_pk(),
        secrets,
        source,
        store,
        config,
    };
    context.run(starting_cursor).await
}

/// Internals: wraps the pieces a restore needs so the page-loop is a
/// straight read of the steps in the module-level docs.
struct RestoreContext {
    scan_pk: [u8; 33],
    spend_pk: PublicKey,
    secrets: StealthSecrets,
    source: Arc<dyn AnnouncementSource>,
    store: InMemoryStore,
    config: RestoreConfig,
}

impl RestoreContext {
    async fn run(
        &self,
        starting_cursor: ScannerCheckpoint,
    ) -> Result<RestoreSummary, RestoreError> {
        let mut summary = RestoreSummary {
            final_cursor: starting_cursor,
            ..RestoreSummary::default()
        };

        loop {
            if (summary.pages_fetched as usize) >= self.config.page_budget {
                return Err(RestoreError::PageBudgetExceeded {
                    budget: self.config.page_budget,
                });
            }

            let page = self
                .source
                .fetch(&summary.final_cursor, self.config.page_limit)
                .await
                .map_err(RestoreError::from_source_error)?;

            if page.is_empty() {
                debug!(
                    pages_fetched = summary.pages_fetched,
                    "Wallet restore: caught up to chain tip"
                );
                break;
            }

            let outcome = scan_page(
                self.secrets.scan_key.as_secret(),
                &self.spend_pk,
                &page,
                &summary.final_cursor,
            );
            summary.pages_fetched += 1;
            self.apply_outcome(&outcome, &mut summary).await;
            self.persist_cursor(&summary.final_cursor);

            if let Some(callback) = &self.config.progress {
                callback(&RestoreProgress {
                    announcements_scanned: summary.announcements_scanned,
                    matches_found: summary.matches_found,
                    pages_fetched: summary.pages_fetched,
                    cursor: summary.final_cursor.clone(),
                });
            }
        }

        info!(
            pages = summary.pages_fetched,
            scanned = summary.announcements_scanned,
            matched = summary.matches_found,
            scan_pk = %hex::encode(self.scan_pk),
            "Wallet restore: complete"
        );

        Ok(summary)
    }

    async fn apply_outcome(&self, outcome: &PageScanOutcome, summary: &mut RestoreSummary) {
        summary.announcements_scanned += outcome.scanned;
        summary.matches_found += outcome.matches.len() as u64;
        summary.final_cursor = outcome.last_seen.clone();
        for matched in &outcome.matches {
            self.persist_match(matched).await;
        }
    }

    async fn persist_match(&self, matched: &StealthMatch) {
        match self.source.fetch_vtxo(matched).await {
            Ok(Some(vtxo)) => self.store.upsert_vtxo(vtxo),
            Ok(None) => self.store.upsert_vtxo(placeholder_vtxo(matched)),
            Err(err) => tracing::warn!(
                %err,
                vtxo_id = %matched.vtxo_id,
                "Wallet restore: VTXO fetch failed; match recorded with placeholder"
            ),
        }
    }

    fn persist_cursor(&self, cursor: &ScannerCheckpoint) {
        self.store
            .set_metadata(CHECKPOINT_METADATA_KEY, cursor.encode());
    }
}

/// Choose the starting cursor: birthday > existing checkpoint > genesis.
fn initial_cursor(store: &InMemoryStore, birthday_height: Option<u32>) -> ScannerCheckpoint {
    if let Some(height) = birthday_height {
        return birthday_cursor(height);
    }
    store
        .get_metadata(CHECKPOINT_METADATA_KEY)
        .and_then(|raw| ScannerCheckpoint::decode(&raw))
        .unwrap_or_default()
}

/// Encode a round height as the scanner's exclusive lower-bound cursor.
fn birthday_cursor(height: u32) -> ScannerCheckpoint {
    ScannerCheckpoint {
        round_id: format!("{:0width$}", height, width = HEIGHT_CURSOR_WIDTH),
        vtxo_id: String::new(),
    }
}

/// Strip an `ARCHIVAL_HORIZON_MARKER` payload out of an error message.
///
/// The marker is followed by the operator's current horizon round id
/// in any of these shapes the gRPC layer might emit:
///
/// ```text
///     BirthdayBeforeArchivalHorizon { current_horizon_round: "round-9" }
///     BirthdayBeforeArchivalHorizon { current_horizon_round: round-9 }
///     BirthdayBeforeArchivalHorizon: round-9
///     BirthdayBeforeArchivalHorizon=round-9
/// ```
fn parse_archival_horizon(message: &str) -> Option<String> {
    let after_marker = message.split_once(ARCHIVAL_HORIZON_MARKER)?.1;
    extract_horizon_round_id(after_marker).map(str::to_owned)
}

/// Return the first non-empty round-id token after the marker. The
/// token is delimited by whitespace, structural characters (`,`, `}`,
/// `"`, backslash for `\"` escaping), or end-of-string.
fn extract_horizon_round_id(tail: &str) -> Option<&str> {
    let trimmed = tail.trim_start_matches([':', '=', ' ', '\t', '\n', '"', '\\', '{']);
    let after_field_label = skip_field_label(trimmed, "current_horizon_round").unwrap_or(trimmed);

    let token: &str = after_field_label
        .split(['"', '\\', ' ', ',', '}', '\n', '\r', '\t'])
        .find(|s| !s.is_empty())
        .unwrap_or("");
    (!token.is_empty()).then_some(token)
}

/// If `tail` begins with `<label>` followed by `:` or `=`, skip past
/// that label and any surrounding whitespace/quote characters.
fn skip_field_label<'a>(tail: &'a str, label: &str) -> Option<&'a str> {
    let trimmed = tail.trim_start();
    let after_label = trimmed.strip_prefix(label)?;
    Some(
        after_label
            .trim_start()
            .trim_start_matches([':', '=', ' ', '"', '\\', '\t']),
    )
}

/// Build a placeholder [`Vtxo`] for a stealth match while the
/// full-fetch path (#558) is still stubbed. Carries only the IDs
/// needed to verify that restore persistence ran.
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

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::error::{ClientError, ClientResult};
    use crate::types::RoundAnnouncement;

    fn fixture_seed() -> [u8; 32] {
        // Same seed pattern as `dark-confidential` test vectors so the
        // derived (scan, spend) keys are stable across crates.
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        seed
    }

    fn derived_spend_pk_hex() -> String {
        let (meta, _) =
            MetaAddress::from_seed(&fixture_seed(), 0, StealthNetwork::Regtest).unwrap();
        hex::encode(meta.spend_pk().serialize())
    }

    fn announcement(round_id: &str, vtxo_id: &str, ephemeral_pubkey: &str) -> RoundAnnouncement {
        RoundAnnouncement {
            cursor: format!("{round_id}\n{vtxo_id}"),
            round_id: round_id.into(),
            vtxo_id: vtxo_id.into(),
            ephemeral_pubkey: ephemeral_pubkey.into(),
        }
    }

    /// Mock source: serves scripted pages, optionally fails the next
    /// fetch with a canned error so we can exercise the
    /// `BirthdayBeforeArchivalHorizon` path.
    #[derive(Default)]
    struct MockSource {
        pages: Mutex<Vec<Vec<RoundAnnouncement>>>,
        fail_next: Mutex<Option<ClientError>>,
        seen_cursors: Mutex<Vec<ScannerCheckpoint>>,
        fetch_calls: AtomicU64,
    }

    impl MockSource {
        fn with_pages(pages: Vec<Vec<RoundAnnouncement>>) -> Self {
            Self {
                pages: Mutex::new(pages),
                ..Self::default()
            }
        }

        fn arm_failure(&self, error: ClientError) {
            *self.fail_next.lock().unwrap() = Some(error);
        }

        fn cursors_observed(&self) -> Vec<ScannerCheckpoint> {
            self.seen_cursors.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AnnouncementSource for MockSource {
        async fn fetch(
            &self,
            cursor: &ScannerCheckpoint,
            _limit: u32,
        ) -> ClientResult<Vec<RoundAnnouncement>> {
            self.fetch_calls.fetch_add(1, Ordering::Relaxed);
            self.seen_cursors.lock().unwrap().push(cursor.clone());

            if let Some(err) = self.fail_next.lock().unwrap().take() {
                return Err(err);
            }
            let mut pages = self.pages.lock().unwrap();
            if pages.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(pages.remove(0))
            }
        }
    }

    #[tokio::test]
    async fn restore_persists_matching_vtxo_and_skips_decoys() {
        let pk_hex = derived_spend_pk_hex();
        let source = Arc::new(MockSource::with_pages(vec![
            vec![
                announcement("round-001", "tx:0", "decoy-a"),
                announcement("round-001", "tx:1", &pk_hex),
                announcement("round-002", "tx:2", "decoy-b"),
            ],
            vec![],
        ]));
        let store = InMemoryStore::new();

        let summary = restore_from_seed(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source.clone(),
            store.clone(),
        )
        .await
        .expect("restore must succeed");

        assert_eq!(summary.announcements_scanned, 3);
        assert_eq!(summary.matches_found, 1);
        assert_eq!(summary.pages_fetched, 1);
        assert_eq!(summary.final_cursor.round_id, "round-002");

        assert!(store.get_vtxo("tx:1").is_some(), "match must be persisted");
        assert!(store.get_vtxo("tx:0").is_none(), "decoy must be skipped");
        assert!(store.get_vtxo("tx:2").is_none(), "decoy must be skipped");
    }

    #[tokio::test]
    async fn restore_advances_cursor_across_multiple_pages() {
        let pk_hex = derived_spend_pk_hex();
        let source = Arc::new(MockSource::with_pages(vec![
            vec![announcement("round-100", "tx:0", &pk_hex)],
            vec![announcement("round-101", "tx:1", "decoy")],
            vec![],
        ]));
        let store = InMemoryStore::new();

        let summary = restore_from_seed(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source.clone(),
            store.clone(),
        )
        .await
        .expect("restore must succeed");

        assert_eq!(summary.pages_fetched, 2);
        assert_eq!(summary.matches_found, 1);
        assert_eq!(summary.final_cursor.round_id, "round-101");

        let cursors = source.cursors_observed();
        assert_eq!(cursors.len(), 3, "three fetches: page1, page2, empty");
        assert!(cursors[0].is_genesis(), "first fetch starts at genesis");
        assert_eq!(cursors[1].round_id, "round-100");
        assert_eq!(cursors[2].round_id, "round-101");
    }

    #[tokio::test]
    async fn restore_starts_from_birthday_height_when_supplied() {
        let source = Arc::new(MockSource::with_pages(vec![vec![]]));
        let store = InMemoryStore::new();

        let summary = restore_from_seed(
            &fixture_seed(),
            0,
            Some(42),
            StealthNetwork::Regtest,
            source.clone(),
            store,
        )
        .await
        .expect("restore must succeed");

        assert_eq!(summary.pages_fetched, 0, "no announcements => no pages");
        let cursors = source.cursors_observed();
        assert_eq!(cursors[0], birthday_cursor(42));
    }

    #[tokio::test]
    async fn restore_resumes_from_persisted_checkpoint_when_birthday_missing() {
        let store = InMemoryStore::new();
        let prior = ScannerCheckpoint {
            round_id: "round-007".into(),
            vtxo_id: "tx:42".into(),
        };
        store.set_metadata(CHECKPOINT_METADATA_KEY, prior.encode());

        let source = Arc::new(MockSource::with_pages(vec![vec![]]));
        let _summary = restore_from_seed(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source.clone(),
            store,
        )
        .await
        .expect("restore must succeed");

        assert_eq!(source.cursors_observed()[0], prior);
    }

    #[tokio::test]
    async fn restore_birthday_overrides_existing_checkpoint() {
        let store = InMemoryStore::new();
        let prior = ScannerCheckpoint {
            round_id: "round-007".into(),
            vtxo_id: "tx:42".into(),
        };
        store.set_metadata(CHECKPOINT_METADATA_KEY, prior.encode());

        let source = Arc::new(MockSource::with_pages(vec![vec![]]));
        let _summary = restore_from_seed(
            &fixture_seed(),
            0,
            Some(99),
            StealthNetwork::Regtest,
            source.clone(),
            store,
        )
        .await
        .expect("restore must succeed");

        let cursor = &source.cursors_observed()[0];
        assert_ne!(cursor, &prior, "birthday must reset the cursor");
        assert_eq!(*cursor, birthday_cursor(99));
    }

    #[tokio::test]
    async fn restore_persists_final_cursor_for_live_scanner_handoff() {
        let pk_hex = derived_spend_pk_hex();
        let source = Arc::new(MockSource::with_pages(vec![
            vec![announcement("round-200", "tx:9", &pk_hex)],
            vec![],
        ]));
        let store = InMemoryStore::new();

        let summary = restore_from_seed(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source,
            store.clone(),
        )
        .await
        .expect("restore must succeed");

        let persisted = store
            .get_metadata(CHECKPOINT_METADATA_KEY)
            .expect("checkpoint must be persisted");
        assert_eq!(persisted, summary.final_cursor.encode());
    }

    #[tokio::test]
    async fn restore_maps_archival_horizon_marker_to_typed_error() {
        let source = Arc::new(MockSource::with_pages(vec![]));
        source.arm_failure(ClientError::Rpc(
            "GetRoundAnnouncements failed: status: FailedPrecondition, \
             message: \"BirthdayBeforeArchivalHorizon { current_horizon_round: \
             \\\"round-9000\\\" }\""
                .into(),
        ));

        let result = restore_from_seed(
            &fixture_seed(),
            0,
            Some(1),
            StealthNetwork::Regtest,
            source,
            InMemoryStore::new(),
        )
        .await;

        match result {
            Err(RestoreError::BirthdayBeforeArchivalHorizon {
                current_horizon_round,
            }) => assert_eq!(current_horizon_round, "round-9000"),
            other => panic!("expected typed horizon error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn restore_propagates_unrelated_source_errors() {
        let source = Arc::new(MockSource::with_pages(vec![]));
        source.arm_failure(ClientError::Connection("boom".into()));

        let result = restore_from_seed(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source,
            InMemoryStore::new(),
        )
        .await;

        assert!(matches!(result, Err(RestoreError::Source(_))));
    }

    #[tokio::test]
    async fn restore_progress_callback_fires_per_page() {
        let pk_hex = derived_spend_pk_hex();
        let source = Arc::new(MockSource::with_pages(vec![
            vec![announcement("round-A", "tx:0", &pk_hex)],
            vec![announcement("round-B", "tx:1", "decoy")],
            vec![],
        ]));

        let events: Arc<Mutex<Vec<RestoreProgress>>> = Arc::new(Mutex::new(Vec::new()));
        let events_for_cb = Arc::clone(&events);
        let progress: ProgressCallback = Arc::new(move |progress: &RestoreProgress| {
            events_for_cb.lock().unwrap().push(progress.clone());
        });

        let summary = restore_from_seed_with(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            source,
            InMemoryStore::new(),
            RestoreConfig {
                progress: Some(progress),
                ..RestoreConfig::default()
            },
        )
        .await
        .expect("restore must succeed");

        let events = events.lock().unwrap();
        assert_eq!(events.len() as u64, summary.pages_fetched);
        assert_eq!(events.last().unwrap().matches_found, 1);
        assert_eq!(events.last().unwrap().pages_fetched, summary.pages_fetched);
    }

    #[tokio::test]
    async fn restore_aborts_when_page_budget_exhausted() {
        // A pathological source that always returns a non-empty page —
        // restore should bail out via `PageBudgetExceeded` rather than
        // looping forever.
        struct InfiniteSource;
        #[async_trait]
        impl AnnouncementSource for InfiniteSource {
            async fn fetch(
                &self,
                _cursor: &ScannerCheckpoint,
                _limit: u32,
            ) -> ClientResult<Vec<RoundAnnouncement>> {
                Ok(vec![announcement("round-x", "tx:0", "decoy")])
            }
        }

        let result = restore_from_seed_with(
            &fixture_seed(),
            0,
            None,
            StealthNetwork::Regtest,
            Arc::new(InfiniteSource),
            InMemoryStore::new(),
            RestoreConfig {
                page_budget: 3,
                ..RestoreConfig::default()
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(RestoreError::PageBudgetExceeded { budget: 3 })
        ));
    }

    #[test]
    fn parse_archival_horizon_handles_multiple_message_shapes() {
        assert_eq!(
            parse_archival_horizon(
                "FailedPrecondition BirthdayBeforeArchivalHorizon { \
                 current_horizon_round: \"round-9\" }"
            ),
            Some("round-9".into())
        );
        assert_eq!(
            parse_archival_horizon("BirthdayBeforeArchivalHorizon: round-9"),
            Some("round-9".into())
        );
        assert_eq!(
            parse_archival_horizon("BirthdayBeforeArchivalHorizon=round-9"),
            Some("round-9".into())
        );
        assert_eq!(parse_archival_horizon("unrelated error"), None);
    }

    #[test]
    fn birthday_cursor_is_zero_padded_for_lex_ordering() {
        assert_eq!(birthday_cursor(7).round_id, "0000000007");
        assert_eq!(birthday_cursor(99).round_id, "0000000099");
        assert!(
            birthday_cursor(7).round_id < birthday_cursor(99).round_id,
            "lex order on the round_id field must follow numeric order"
        );
        assert!(birthday_cursor(7).vtxo_id.is_empty());
    }
}
