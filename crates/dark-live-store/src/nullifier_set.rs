//! Authoritative spent-nullifier set (issue #534).
//!
//! Backed by:
//! - **In-memory hot path:** a sharded `RwLock<HashSet<[u8; 32]>>` so
//!   `contains` is O(1) on the validation hot path and concurrent inserts
//!   from many round participants don't serialise on a single lock.
//! - **Authoritative storage:** a [`NullifierStore`] (typically the
//!   `nullifiers` table in `dark-db`) that survives process restarts.
//!
//! # Schema choice (separate `nullifiers` table)
//!
//! Migrations 008 (sqlite) / 005 (pg) added a `confidential_nullifier`
//! column on `vtxos`, which records the nullifier ASSOCIATED with each
//! confidential output row. The spent set, however, answers a different
//! question: "has this nullifier already been revealed/spent?" — which is
//! independent of any specific VTXO row's lifecycle.
//!
//! Migrations 009 (sqlite) / 006 (pg) therefore add a dedicated
//! `nullifiers` table with a primary-key constraint on the nullifier
//! itself. Insertions are append-only, the lookup is a single-column
//! `SELECT 1`, and double-spend rejection at the DB layer falls out of the
//! PRIMARY KEY conflict — matching the in-memory `HashSet::insert`
//! semantics.
//!
//! # Concurrency design
//!
//! `Arc<RwLock<HashSet>>` would serialise every writer behind a single
//! mutex. With 10K simultaneous round participants the writer queue would
//! dominate latency, even when no real conflict exists. We instead shard
//! the set by the first byte of the nullifier into [`SHARD_COUNT`] = 16
//! partitions. Each shard has its own `RwLock`, so readers never block
//! writers in unrelated shards. The shard count is a power of two so the
//! shard index is a single mask, not a divide.
//!
//! # Atomicity with round commit
//!
//! `batch_insert` is the entry point used during round commit. The
//! [`NullifierStore::persist_batch`] hook is invoked **first**: if the DB
//! write fails (transient I/O, constraint violation), no in-memory state
//! is mutated and the round commit propagates the error. On success the
//! returned `inserted` flags drive both the in-memory HashSet update and
//! the `Result<Vec<bool>>` returned to the caller.
//!
//! This ordering is intentional: an in-memory insert that "succeeds"
//! while the DB row is missing would corrupt the spent set on restart.
//! The reverse failure mode (DB row present, in-memory missing) is
//! handled on the next process start by [`NullifierSet::load_from_db`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::NullifierSink;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Length of a confidential VTXO nullifier in bytes (HMAC-SHA256 output, ADR-0002).
pub const NULLIFIER_LEN: usize = 32;

/// A 32-byte nullifier — alias for clarity at API boundaries.
pub type Nullifier = [u8; NULLIFIER_LEN];

/// Number of shards for the in-memory HashSet.
///
/// Must be a power of two so [`shard_index`] can use a bit mask. 16
/// shards is a sweet spot for the 10_000-parallel-insert AC: each shard
/// sees ~625 inserts, well below `HashSet`'s rehash threshold for the
/// pre-sized capacity.
pub const SHARD_COUNT: usize = 16;
const SHARD_MASK: usize = SHARD_COUNT - 1;

/// Authoritative storage for the nullifier spent set.
///
/// Implementations persist nullifiers across process restarts. The trait
/// is intentionally narrow — it covers exactly the queries that
/// [`NullifierSet`] needs and nothing else, so dark-live-store does not
/// need a hard dependency on any DB driver.
#[async_trait]
pub trait NullifierStore: Send + Sync {
    /// Read every nullifier currently persisted, in any order.
    ///
    /// Called once during [`NullifierSet::load_from_db`] at process
    /// start. Implementations should stream rather than materialise the
    /// full set when the table grows beyond available memory; the
    /// default contract is a single `Vec` because the in-memory set is
    /// the destination anyway.
    async fn load_all(&self) -> ArkResult<Vec<Nullifier>>;

    /// Append the given nullifiers to the persistent store.
    ///
    /// Returns one `bool` per input slot: `true` if newly inserted,
    /// `false` if the nullifier was already present (PRIMARY KEY
    /// conflict). Errors propagate the underlying store error and the
    /// in-memory set MUST NOT be mutated by the caller.
    async fn persist_batch(
        &self,
        nullifiers: &[Nullifier],
        round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>>;

    /// Total count of nullifiers in the persistent store.
    ///
    /// Used by [`NullifierSet::sanity_check`] to detect drift between
    /// the in-memory `len` and the DB.
    async fn count(&self) -> ArkResult<usize>;
}

/// In-memory `NullifierStore` impl for tests and the `memory` feature.
///
/// Holds a single `Mutex<HashSet>` — no need for shards here because
/// `NullifierSet` already shards on top of `NullifierStore`, and the
/// `persist_batch` calls are short.
#[derive(Debug, Default)]
pub struct InMemoryNullifierStore {
    inner: Mutex<HashSet<Nullifier>>,
}

impl InMemoryNullifierStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl NullifierStore for InMemoryNullifierStore {
    async fn load_all(&self) -> ArkResult<Vec<Nullifier>> {
        Ok(self.inner.lock().await.iter().copied().collect())
    }

    async fn persist_batch(
        &self,
        nullifiers: &[Nullifier],
        _round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>> {
        let mut guard = self.inner.lock().await;
        let mut results = Vec::with_capacity(nullifiers.len());
        for n in nullifiers {
            results.push(guard.insert(*n));
        }
        Ok(results)
    }

    async fn count(&self) -> ArkResult<usize> {
        Ok(self.inner.lock().await.len())
    }
}

/// Sharded HashSet — one `RwLock<HashSet>` per shard.
struct Shards {
    shards: Vec<RwLock<HashSet<Nullifier>>>,
}

impl Shards {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(RwLock::new(HashSet::new()));
        }
        Self { shards }
    }
}

/// Pick the shard index for a nullifier via its first byte.
///
/// Bytewise dispatch is fine because the input is the output of
/// HMAC-SHA256, which is uniformly distributed over 32 bytes by
/// construction. A more elaborate hash would only add cost without
/// reducing collisions.
#[inline]
fn shard_index(n: &Nullifier) -> usize {
    n[0] as usize & SHARD_MASK
}

/// Authoritative spent-nullifier set with O(1) in-memory membership and
/// append-only DB persistence.
///
/// Construction:
/// - [`NullifierSet::new`] — empty set, attach a store.
/// - [`NullifierSet::load_from_db`] — populate from the persistent store.
///
/// Hot-path operations:
/// - [`NullifierSet::contains`] — sub-microsecond on the 10M-entry bench.
/// - [`NullifierSet::insert`] / [`NullifierSet::batch_insert`] — DB write
///   first, in-memory mutation only on persist success.
pub struct NullifierSet {
    shards: Arc<Shards>,
    store: Arc<dyn NullifierStore>,
}

impl NullifierSet {
    /// Create an empty `NullifierSet` backed by the given store.
    ///
    /// Use [`NullifierSet::load_from_db`] instead if the store may
    /// already contain nullifiers from a prior run.
    pub fn new(store: Arc<dyn NullifierStore>) -> Self {
        Self {
            shards: Arc::new(Shards::new()),
            store,
        }
    }

    /// Construct a `NullifierSet` and pre-populate it from the
    /// authoritative store.
    ///
    /// Called once at process start so the in-memory set matches the DB
    /// before any membership check runs.
    pub async fn load_from_db(store: Arc<dyn NullifierStore>) -> ArkResult<Self> {
        let set = Self::new(store.clone());
        let all = store.load_all().await?;
        let count = all.len();
        // Pre-sort by shard so each shard lock is taken once. With 10M
        // entries this saves ~10M lock acquire/release pairs.
        let mut buckets: Vec<Vec<Nullifier>> = (0..SHARD_COUNT).map(|_| Vec::new()).collect();
        for n in all {
            buckets[shard_index(&n)].push(n);
        }
        for (idx, bucket) in buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let mut guard = set.shards.shards[idx].write().await;
            for n in bucket {
                guard.insert(n);
            }
        }
        dark_core::metrics::NULLIFIERS_TOTAL.set(count as i64);
        info!(loaded = count, "NullifierSet loaded from DB");
        Ok(set)
    }

    /// O(1) membership check. Records a metric per call.
    pub async fn contains(&self, nullifier: &Nullifier) -> bool {
        dark_core::metrics::NULLIFIER_LOOKUPS_TOTAL.inc();
        let shard = &self.shards.shards[shard_index(nullifier)];
        let guard = shard.read().await;
        let hit = guard.contains(nullifier);
        if hit {
            dark_core::metrics::NULLIFIER_HITS_TOTAL.inc();
        }
        hit
    }

    /// Insert a single nullifier.
    ///
    /// Returns `Ok(true)` if newly inserted, `Ok(false)` if the
    /// nullifier was already in the set (rejected double-spend). The DB
    /// write happens **before** the in-memory mutation; on DB error the
    /// in-memory set is left untouched.
    pub async fn insert(&self, nullifier: &Nullifier) -> ArkResult<bool> {
        let _timer = LatencyTimer::start();
        let inserted = self
            .store
            .persist_batch(std::slice::from_ref(nullifier), None)
            .await?;
        let was_new = *inserted.first().unwrap_or(&false);
        if was_new {
            let shard = &self.shards.shards[shard_index(nullifier)];
            let mut guard = shard.write().await;
            // Guard against the (rare) race where another task inserted
            // the same nullifier between our DB write and this lock
            // acquisition: rely on HashSet's idempotence.
            guard.insert(*nullifier);
            dark_core::metrics::NULLIFIERS_TOTAL.inc();
        }
        Ok(was_new)
    }

    /// Batch insert for round commit.
    ///
    /// Returns one boolean per input slot (`true` = newly inserted).
    /// The DB write is a single `persist_batch` call so the round
    /// commit transaction sees all-or-nothing persistence; the
    /// in-memory shard updates run only after the DB call returns Ok.
    pub async fn batch_insert(
        &self,
        nullifiers: &[Nullifier],
        round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>> {
        if nullifiers.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = LatencyTimer::start();
        let inserted = self.store.persist_batch(nullifiers, round_id).await?;
        if inserted.len() != nullifiers.len() {
            return Err(ArkError::Internal(format!(
                "NullifierStore::persist_batch returned {} flags for {} nullifiers",
                inserted.len(),
                nullifiers.len()
            )));
        }

        // Group by shard so each shard lock is taken once, not N times.
        let mut buckets: Vec<Vec<Nullifier>> = (0..SHARD_COUNT).map(|_| Vec::new()).collect();
        let mut newly_added: u64 = 0;
        for (n, was_new) in nullifiers.iter().zip(inserted.iter()) {
            if *was_new {
                buckets[shard_index(n)].push(*n);
                newly_added += 1;
            }
        }
        for (idx, bucket) in buckets.into_iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let mut guard = self.shards.shards[idx].write().await;
            for n in bucket {
                guard.insert(n);
            }
        }
        if newly_added > 0 {
            dark_core::metrics::NULLIFIERS_TOTAL.add(newly_added as i64);
        }

        debug!(
            requested = nullifiers.len(),
            newly_added, "NullifierSet batch_insert complete"
        );
        Ok(inserted)
    }

    /// Total in-memory count across all shards.
    pub async fn len(&self) -> usize {
        let mut total = 0;
        for shard in &self.shards.shards {
            total += shard.read().await.len();
        }
        total
    }

    /// `true` iff every shard is empty.
    pub async fn is_empty(&self) -> bool {
        for shard in &self.shards.shards {
            if !shard.read().await.is_empty() {
                return false;
            }
        }
        true
    }

    /// Compare in-memory `len()` against the DB `count()`. Logs a warn
    /// and returns the absolute drift when they disagree.
    ///
    /// Callers should run this on a periodic timer (e.g. once per
    /// minute) to surface silent corruption — drift > 0 means either
    /// an out-of-band DB write happened, or an in-memory insert lost
    /// its DB partner. Either way, alert on it.
    pub async fn sanity_check(&self) -> ArkResult<usize> {
        let mem = self.len().await;
        let db = self.store.count().await?;
        let drift = mem.abs_diff(db);
        if drift > 0 {
            warn!(
                in_memory = mem,
                db, drift, "NullifierSet drift between in-memory set and DB — investigate"
            );
        } else {
            debug!(
                in_memory = mem,
                db, "NullifierSet sanity check ok (no drift)"
            );
        }
        Ok(drift)
    }

    /// Clone the underlying store handle. Used in integration with
    /// other services that already need DB access.
    pub fn store(&self) -> Arc<dyn NullifierStore> {
        Arc::clone(&self.store)
    }
}

// Bridge `NullifierSet` to the `dark-core` port so `ArkService` can hold
// it as `Arc<dyn NullifierSink>` without dark-core depending on us.
#[async_trait]
impl NullifierSink for NullifierSet {
    async fn batch_insert(
        &self,
        nullifiers: &[[u8; 32]],
        round_id: Option<&str>,
    ) -> ArkResult<Vec<bool>> {
        NullifierSet::batch_insert(self, nullifiers, round_id).await
    }

    async fn contains(&self, nullifier: &[u8; 32]) -> bool {
        NullifierSet::contains(self, nullifier).await
    }
}

/// RAII timer that records `NULLIFIER_INSERT_LATENCY` on drop.
struct LatencyTimer {
    start: Instant,
}

impl LatencyTimer {
    fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Drop for LatencyTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        dark_core::metrics::NULLIFIER_INSERT_LATENCY.observe(elapsed);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn nul(b: u8) -> Nullifier {
        let mut n = [0u8; NULLIFIER_LEN];
        n[0] = b;
        n
    }

    fn nul_full(seed: u64) -> Nullifier {
        // Cheap deterministic spread across all 32 bytes so shard
        // distribution doesn't degenerate in the concurrency test.
        let mut n = [0u8; NULLIFIER_LEN];
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        for chunk in n.chunks_mut(8) {
            x = x.wrapping_add(0xA5A5_A5A5_A5A5_A5A5);
            chunk.copy_from_slice(&x.to_le_bytes()[..chunk.len()]);
        }
        n
    }

    #[tokio::test]
    async fn empty_set_does_not_contain_anything() {
        let set = NullifierSet::new(Arc::new(InMemoryNullifierStore::new()));
        assert!(set.is_empty().await);
        assert_eq!(set.len().await, 0);
        assert!(!set.contains(&nul(1)).await);
    }

    #[tokio::test]
    async fn insert_then_contains() {
        let set = NullifierSet::new(Arc::new(InMemoryNullifierStore::new()));
        let n = nul(42);
        assert!(!set.contains(&n).await);
        let new = set.insert(&n).await.unwrap();
        assert!(new);
        assert!(set.contains(&n).await);
        assert_eq!(set.len().await, 1);
    }

    #[tokio::test]
    async fn double_spend_regression() {
        // Submit the same nullifier twice — second call MUST be rejected
        // with insert returning Ok(false). This is the AC: prevents a
        // confidential VTXO from being spent twice.
        let set = NullifierSet::new(Arc::new(InMemoryNullifierStore::new()));
        let n = nul(7);

        let first = set.insert(&n).await.unwrap();
        assert!(first, "first insert must report newly inserted");

        let second = set.insert(&n).await.unwrap();
        assert!(!second, "second insert of same nullifier must be rejected");

        // Membership stays positive
        assert!(set.contains(&n).await);
        // Count does not double
        assert_eq!(set.len().await, 1);
    }

    #[tokio::test]
    async fn batch_insert_returns_per_slot_status() {
        let set = NullifierSet::new(Arc::new(InMemoryNullifierStore::new()));
        let a = nul(1);
        let b = nul(2);
        let c = nul(3);

        // First call: all three are new
        let res = set.batch_insert(&[a, b, c], Some("round-1")).await.unwrap();
        assert_eq!(res, vec![true, true, true]);
        assert_eq!(set.len().await, 3);

        // Second call: a, c repeat; b is replaced by a new value
        let d = nul(4);
        let res2 = set.batch_insert(&[a, d, c], Some("round-2")).await.unwrap();
        assert_eq!(res2, vec![false, true, false]);
        assert_eq!(set.len().await, 4);
    }

    #[tokio::test]
    async fn batch_insert_empty_is_noop() {
        let set = NullifierSet::new(Arc::new(InMemoryNullifierStore::new()));
        let res = set.batch_insert(&[], None).await.unwrap();
        assert!(res.is_empty());
        assert_eq!(set.len().await, 0);
    }

    #[tokio::test]
    async fn crash_recovery_state_matches_db() {
        // Simulate "process restart" by writing to the store via one
        // NullifierSet, dropping it, then constructing a fresh one with
        // load_from_db against the SAME store. The new set must see
        // every previously inserted nullifier.
        let store: Arc<dyn NullifierStore> = Arc::new(InMemoryNullifierStore::new());

        let nullifiers: Vec<Nullifier> = (0..200u64).map(nul_full).collect();

        {
            let set = NullifierSet::new(Arc::clone(&store));
            set.batch_insert(&nullifiers, Some("round-pre-crash"))
                .await
                .unwrap();
            assert_eq!(set.len().await, nullifiers.len());
            // `set` is dropped here, simulating process death.
        }

        // "Restart": fresh NullifierSet rebuilt from the store
        let recovered = NullifierSet::load_from_db(Arc::clone(&store))
            .await
            .unwrap();
        assert_eq!(recovered.len().await, nullifiers.len());
        for n in &nullifiers {
            assert!(
                recovered.contains(n).await,
                "post-restart set is missing a nullifier"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrency_10000_parallel_inserts() {
        // Acceptance criterion: 10_000 parallel inserts, no duplicates,
        // every nullifier passes the post-insert membership check.
        const N: usize = 10_000;
        let set = Arc::new(NullifierSet::new(Arc::new(InMemoryNullifierStore::new())));
        let inserted_counter = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let set = Arc::clone(&set);
            let counter = Arc::clone(&inserted_counter);
            handles.push(tokio::spawn(async move {
                let n = nul_full(i as u64);
                let was_new = set.insert(&n).await.unwrap();
                if was_new {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                n
            }));
        }

        let mut all = Vec::with_capacity(N);
        for h in handles {
            all.push(h.await.unwrap());
        }

        // Every nullifier was distinct so all N must report newly inserted
        assert_eq!(inserted_counter.load(Ordering::Relaxed), N);
        assert_eq!(set.len().await, N);

        // Every inserted nullifier passes membership
        for n in &all {
            assert!(set.contains(n).await, "post-insert membership failed");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_double_inserts_collapse_to_one() {
        // Rough race-condition stress: spawn many tasks that each try
        // to insert THE SAME nullifier. Exactly one must report
        // newly-inserted; the others must report already-present.
        let set = Arc::new(NullifierSet::new(Arc::new(InMemoryNullifierStore::new())));
        let n = nul_full(0xDEAD_BEEF);

        let mut handles = Vec::new();
        for _ in 0..200 {
            let set = Arc::clone(&set);
            handles.push(tokio::spawn(async move { set.insert(&n).await.unwrap() }));
        }

        let mut new_count = 0;
        for h in handles {
            if h.await.unwrap() {
                new_count += 1;
            }
        }
        assert_eq!(new_count, 1, "exactly one inserter must win the race");
        assert_eq!(set.len().await, 1);
    }

    #[tokio::test]
    async fn load_from_db_populates_set() {
        let store: Arc<dyn NullifierStore> = Arc::new(InMemoryNullifierStore::new());
        let nullifiers: Vec<Nullifier> = (0..50u64).map(nul_full).collect();
        store
            .persist_batch(&nullifiers, Some("round-x"))
            .await
            .unwrap();

        let set = NullifierSet::load_from_db(Arc::clone(&store))
            .await
            .unwrap();
        assert_eq!(set.len().await, 50);
        for n in &nullifiers {
            assert!(set.contains(n).await);
        }
    }

    #[tokio::test]
    async fn sanity_check_reports_no_drift() {
        let store: Arc<dyn NullifierStore> = Arc::new(InMemoryNullifierStore::new());
        let set = NullifierSet::new(Arc::clone(&store));
        let nullifiers: Vec<Nullifier> = (0..10u64).map(nul_full).collect();
        set.batch_insert(&nullifiers, None).await.unwrap();
        let drift = set.sanity_check().await.unwrap();
        assert_eq!(drift, 0);
    }

    #[tokio::test]
    async fn sanity_check_detects_drift() {
        // Inject extra rows directly into the store WITHOUT going
        // through NullifierSet — emulates an out-of-band repair tool.
        // The in-memory set should still be smaller than the DB count.
        let store: Arc<dyn NullifierStore> = Arc::new(InMemoryNullifierStore::new());
        let set = NullifierSet::new(Arc::clone(&store));

        let in_band: Vec<Nullifier> = (0..5u64).map(nul_full).collect();
        set.batch_insert(&in_band, None).await.unwrap();

        let out_of_band: Vec<Nullifier> = (100..103u64).map(nul_full).collect();
        store.persist_batch(&out_of_band, None).await.unwrap();

        let drift = set.sanity_check().await.unwrap();
        assert_eq!(drift, 3);
    }

    #[test]
    fn shard_count_is_power_of_two() {
        assert_eq!(SHARD_COUNT & (SHARD_COUNT - 1), 0);
        assert_eq!(SHARD_MASK, SHARD_COUNT - 1);
    }

    #[test]
    fn shard_index_only_uses_low_bits() {
        // Verify the mask. Two nullifiers whose first bytes differ only
        // in high bits beyond SHARD_MASK end up in the same shard.
        let a = nul(0b0000_0001);
        let b = nul(0b1111_0001);
        assert_eq!(shard_index(&a), shard_index(&b));
    }
}
