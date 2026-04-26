//! Prometheus metrics for the Ark protocol server.
//!
//! Provides counters and gauges for monitoring:
//! - Round lifecycle (created, completed, failed)
//! - Participant activity
//! - VTXO management
//! - Sweep operations
//!
//! # Usage
//!
//! ```rust,no_run
//! use dark_core::metrics;
//!
//! // Record a new round
//! metrics::ROUNDS_TOTAL.inc();
//! metrics::ACTIVE_ROUNDS.inc();
//!
//! // When round completes
//! metrics::ACTIVE_ROUNDS.dec();
//! metrics::ROUNDS_COMPLETED.inc();
//! ```

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

/// Global metrics registry for dark.
pub static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    let registry = Registry::new_custom(Some("dark".to_string()), None)
        .expect("failed to create metrics registry");
    register_all(&registry);
    registry
});

// ---------------------------------------------------------------------------
// Round metrics
// ---------------------------------------------------------------------------

/// Total number of rounds initiated.
pub static ROUNDS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("rounds_total", "Total number of rounds initiated")
        .expect("metric creation failed")
});

/// Total number of rounds completed successfully.
pub static ROUNDS_COMPLETED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("rounds_completed_total", "Rounds completed successfully")
        .expect("metric creation failed")
});

/// Total number of rounds that failed.
pub static ROUNDS_FAILED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("rounds_failed_total", "Rounds that failed").expect("metric creation failed")
});

/// Number of currently active rounds.
pub static ACTIVE_ROUNDS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("active_rounds", "Currently active rounds").expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Per-round VTXO-variant counters (issue #541)
// ---------------------------------------------------------------------------
//
// Both counters are *cumulative totals*: each call to `complete_round` adds
// the round's per-variant count via `inc_by(n)`. Consumers can derive
// per-round histograms by deltas. We emit aggregate counts only (no per-owner
// labels) so the metric does not become a side-channel that leaks which
// users used the confidential variant.

/// Cumulative total number of confidential VTXOs that have appeared in any
/// completed round, summed across rounds. Per-round delta = the round's
/// confidential VTXO count.
pub static ROUND_CONFIDENTIAL_TX_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "round_confidential_tx_count",
        "Cumulative count of confidential VTXOs across all completed rounds (no per-owner labels)",
    )
    .expect("metric creation failed")
});

/// Cumulative total number of transparent VTXOs that have appeared in any
/// completed round, summed across rounds. Per-round delta = the round's
/// transparent VTXO count.
pub static ROUND_TRANSPARENT_TX_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "round_transparent_tx_count",
        "Cumulative count of transparent VTXOs across all completed rounds (no per-owner labels)",
    )
    .expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Participant metrics
// ---------------------------------------------------------------------------

/// Total number of participants registered across all rounds.
pub static PARTICIPANTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("participants_total", "Total participants registered")
        .expect("metric creation failed")
});

/// Current number of participants in active rounds.
pub static ACTIVE_PARTICIPANTS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("active_participants", "Participants in active rounds")
        .expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// VTXO metrics
// ---------------------------------------------------------------------------

/// Total number of VTXOs created.
pub static VTXOS_CREATED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("vtxos_created_total", "Total VTXOs created").expect("metric creation failed")
});

/// Number of currently active (unspent, unexpired) VTXOs.
pub static VTXOS_ACTIVE: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("vtxos_active", "Currently active VTXOs").expect("metric creation failed")
});

/// Total number of VTXOs spent.
pub static VTXOS_SPENT: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("vtxos_spent_total", "Total VTXOs spent").expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Nullifier-set metrics (#534)
// ---------------------------------------------------------------------------

/// Number of nullifiers currently held in the in-memory spent set.
///
/// Updated on every successful insert / batch_insert / load_from_db.
pub static NULLIFIERS_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "nullifiers_total",
        "Number of nullifiers in the in-memory spent set",
    )
    .expect("metric creation failed")
});

/// Total number of `contains` lookups against the nullifier set.
pub static NULLIFIER_LOOKUPS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "nullifier_lookups_total",
        "Total number of nullifier-set membership lookups",
    )
    .expect("metric creation failed")
});

/// Total number of `contains` lookups that returned `true` (nullifier
/// already in the set — i.e., a double-spend would have been rejected).
pub static NULLIFIER_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "nullifier_hits_total",
        "Total nullifier-set lookups that returned hit (already-spent)",
    )
    .expect("metric creation failed")
});

/// Histogram of `insert` / `batch_insert` latencies in seconds.
///
/// Buckets cover the in-memory hot path (1us..1ms) and the DB-write
/// tail (1ms..1s) so a single histogram is enough to spot regressions
/// in either layer.
pub static NULLIFIER_INSERT_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "nullifier_insert_latency_seconds",
            "Latency of nullifier-set insert/batch_insert operations (seconds)",
        )
        .buckets(vec![
            0.000_001, 0.000_010, 0.000_100, 0.001, 0.010, 0.100, 1.0,
        ]),
    )
    .expect("metric creation failed")
});

/// Histogram of the round-commit critical section that wraps the
/// nullifier-insert + output-queue (VTXO persistence) atomic block
/// (issue #539).
///
/// Distinct from `NULLIFIER_INSERT_LATENCY`: that histogram covers only
/// the `NullifierSet::insert/batch_insert` call, while this one spans
/// the entire critical section in `ArkService::commit_round_atomic` so
/// regressions in the surrounding lock + VTXO persistence show up
/// separately from raw nullifier-store latency.
pub static NULLIFIER_COMMIT_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "nullifier_commit_latency_seconds",
            "Latency of the atomic round-commit nullifier+VTXO critical section (seconds)",
        )
        .buckets(vec![0.000_010, 0.000_100, 0.001, 0.010, 0.100, 1.0, 10.0]),
    )
    .expect("metric creation failed")
});

/// Counter of detected drifts between the in-memory nullifier set and
/// the DB count after a round commit (issue #539).
///
/// Incremented every time the post-commit check finds the in-memory
/// `NullifierSet::len()` and `NullifierStore::count()` differ. Pairs
/// with a warn-log so operators can investigate the discrepancy.
pub static NULLIFIER_DRIFT_DETECTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "nullifier_drift_detected_total",
        "Times a drift between in-memory nullifier set and DB count was observed",
    )
    .expect("metric creation failed")
});

/// Counter of in-memory nullifier-set rollbacks triggered when the
/// surrounding atomic round-commit step fails after a successful
/// nullifier insert (issue #539).
pub static NULLIFIER_ROLLBACKS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "nullifier_rollbacks_total",
        "Times in-memory nullifier inserts were rolled back due to a downstream commit failure",
    )
    .expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Live VTXO store metrics (#535)
// ---------------------------------------------------------------------------

/// Number of VTXOs currently held in the in-memory live store.
///
/// Updated on every successful insert / remove / hydration. Combined gauge
/// across both transparent and confidential variants — operators can
/// disambiguate via [`LIVE_VTXOS_CONFIDENTIAL_TOTAL`] if needed.
pub static LIVE_VTXOS_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "live_vtxos_total",
        "Number of VTXOs currently held in the in-memory live store",
    )
    .expect("metric creation failed")
});

/// Number of confidential VTXOs in the in-memory live store.
///
/// Subset of [`LIVE_VTXOS_TOTAL`]. The transparent count is `LIVE_VTXOS_TOTAL
/// - LIVE_VTXOS_CONFIDENTIAL_TOTAL`.
pub static LIVE_VTXOS_CONFIDENTIAL_TOTAL: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new(
        "live_vtxos_confidential_total",
        "Number of confidential VTXOs currently held in the in-memory live store",
    )
    .expect("metric creation failed")
});

/// Total lookups against the live VTXO store (by outpoint OR nullifier).
///
/// Pair with [`LIVE_VTXO_LOOKUP_HITS_TOTAL`] for hit rate; ratio is the
/// "index hit rate" called out in #535.
pub static LIVE_VTXO_LOOKUPS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "live_vtxo_lookups_total",
        "Total live-VTXO-store lookups (by outpoint or nullifier)",
    )
    .expect("metric creation failed")
});

/// Lookups against the live VTXO store that returned a hit.
pub static LIVE_VTXO_LOOKUP_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "live_vtxo_lookup_hits_total",
        "Total live-VTXO-store lookups that returned a hit",
    )
    .expect("metric creation failed")
});

/// Total nullifier-index lookups (subset of [`LIVE_VTXO_LOOKUPS_TOTAL`]).
///
/// Useful for splitting hit-rate by lookup mode without extra labels.
pub static LIVE_VTXO_NULLIFIER_LOOKUPS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "live_vtxo_nullifier_lookups_total",
        "Total live-VTXO-store lookups that go via the nullifier index",
    )
    .expect("metric creation failed")
});

/// Nullifier-index lookups that returned a hit.
pub static LIVE_VTXO_NULLIFIER_HITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "live_vtxo_nullifier_hits_total",
        "Total live-VTXO-store nullifier-index lookups that returned a hit",
    )
    .expect("metric creation failed")
});

/// Histogram of `lookup` latency in seconds for the live VTXO store.
///
/// Buckets cover the in-memory hot path (1us..1ms); tail buckets to
/// ~100ms catch a hydration / DB miss when one is wired in.
pub static LIVE_VTXO_LOOKUP_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "live_vtxo_lookup_latency_seconds",
            "Latency of live-VTXO-store lookups (seconds)",
        )
        .buckets(vec![
            0.000_000_5,
            0.000_001,
            0.000_002,
            0.000_005,
            0.000_010,
            0.000_050,
            0.000_100,
            0.001,
            0.010,
            0.100,
        ]),
    )
    .expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Sweep metrics
// ---------------------------------------------------------------------------

/// Total number of sweep operations executed.
pub static SWEEPS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("sweeps_total", "Total sweep operations executed")
        .expect("metric creation failed")
});

/// Total number of VTXOs reclaimed via sweeps.
pub static SWEEPS_VTXOS_RECLAIMED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new(
        "sweeps_vtxos_reclaimed_total",
        "VTXOs reclaimed via sweep operations",
    )
    .expect("metric creation failed")
});

// ---------------------------------------------------------------------------
// Confidential validation error metrics (#544)
// ---------------------------------------------------------------------------

/// Total confidential-validation rejections, partitioned by `reason`.
///
/// One bucket per `ConfidentialValidationError` variant. The `reason`
/// label set is closed and produced by
/// `ConfidentialValidationError::reason()`, so cardinality stays bounded:
///
/// - `invalid_range_proof`
/// - `invalid_balance_proof`
/// - `nullifier_already_spent`
/// - `unknown_input_vtxo`
/// - `fee_too_low`
/// - `memo_too_large`
/// - `malformed_commitment`
/// - `version_mismatch`
///
/// Increment via [`record_confidential_validation_error`] (called from
/// `ConfidentialValidationError::observe()`).
pub static CONFIDENTIAL_VALIDATION_ERROR_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    IntCounterVec::new(
        Opts::new(
            "confidential_validation_error_total",
            "Total confidential validation rejections, by reason",
        ),
        &["reason"],
    )
    .expect("metric creation failed")
});

/// Closed list of `reason` labels exposed on
/// `confidential_validation_error_total`. Mirrors the variants of
/// `ConfidentialValidationError::reason()`. Kept in this module so
/// pre-registering all label values (so they appear in `/metrics` with
/// value `0` even before the first error of that kind) stays a one-line
/// change when a new variant is added.
pub const CONFIDENTIAL_VALIDATION_ERROR_REASONS: &[&str] = &[
    "invalid_range_proof",
    "invalid_balance_proof",
    "nullifier_already_spent",
    "unknown_input_vtxo",
    "fee_too_low",
    "memo_too_large",
    "malformed_commitment",
    "version_mismatch",
];

/// Increment `confidential_validation_error_total{reason}` by 1.
///
/// Prefer calling `ConfidentialValidationError::observe()` instead of
/// invoking this directly — it ties the metric to error construction so
/// it cannot be skipped at a call-site.
pub fn record_confidential_validation_error(reason: &str) {
    CONFIDENTIAL_VALIDATION_ERROR_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Read the current value of
/// `confidential_validation_error_total{reason=<reason>}`.
///
/// Public for use by tests in this crate that assert the counter
/// increments. Returns 0 if the label has never been touched.
pub fn confidential_validation_error_total_for(reason: &str) -> u64 {
    CONFIDENTIAL_VALIDATION_ERROR_TOTAL
        .with_label_values(&[reason])
        .get()
}

// ---------------------------------------------------------------------------
// Registration helper
// ---------------------------------------------------------------------------

fn register_all(registry: &Registry) {
    let counters: Vec<&IntCounter> = vec![
        &ROUNDS_TOTAL,
        &ROUNDS_COMPLETED,
        &ROUNDS_FAILED,
        &PARTICIPANTS_TOTAL,
        &VTXOS_CREATED,
        &VTXOS_SPENT,
        &SWEEPS_TOTAL,
        &SWEEPS_VTXOS_RECLAIMED,
        &NULLIFIER_LOOKUPS_TOTAL,
        &NULLIFIER_HITS_TOTAL,
        &LIVE_VTXO_LOOKUPS_TOTAL,
        &LIVE_VTXO_LOOKUP_HITS_TOTAL,
        &LIVE_VTXO_NULLIFIER_LOOKUPS_TOTAL,
        &LIVE_VTXO_NULLIFIER_HITS_TOTAL,
        &NULLIFIER_DRIFT_DETECTED_TOTAL,
        &NULLIFIER_ROLLBACKS_TOTAL,
        &ROUND_CONFIDENTIAL_TX_COUNT,
        &ROUND_TRANSPARENT_TX_COUNT,
    ];
    let gauges: Vec<&IntGauge> = vec![
        &ACTIVE_ROUNDS,
        &ACTIVE_PARTICIPANTS,
        &VTXOS_ACTIVE,
        &NULLIFIERS_TOTAL,
        &LIVE_VTXOS_TOTAL,
        &LIVE_VTXOS_CONFIDENTIAL_TOTAL,
    ];

    for c in counters {
        registry
            .register(Box::new(c.clone()))
            .expect("register counter");
    }
    for g in gauges {
        registry
            .register(Box::new(g.clone()))
            .expect("register gauge");
    }
    registry
        .register(Box::new(NULLIFIER_INSERT_LATENCY.clone()))
        .expect("register histogram");
    registry
        .register(Box::new(LIVE_VTXO_LOOKUP_LATENCY.clone()))
        .expect("register histogram");
    registry
        .register(Box::new(NULLIFIER_COMMIT_LATENCY.clone()))
        .expect("register histogram");

    registry
        .register(Box::new(CONFIDENTIAL_VALIDATION_ERROR_TOTAL.clone()))
        .expect("register confidential_validation_error_total");

    // Pre-touch each `reason` label so all buckets appear at 0 in the
    // first `/metrics` scrape, even if no error of that kind has fired
    // yet. This is what lets a Grafana panel grouped by `reason` show a
    // stable legend instead of vanishing labels.
    for reason in CONFIDENTIAL_VALIDATION_ERROR_REASONS {
        let _ = CONFIDENTIAL_VALIDATION_ERROR_TOTAL.with_label_values(&[reason]);
    }
}

/// Encode all registered metrics into Prometheus text format.
///
/// Returns the text body suitable for serving at `/metrics`.
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encode metrics");
    String::from_utf8(buffer).expect("metrics are valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_encode() {
        // Trigger lazy registration
        ROUNDS_TOTAL.inc();
        ACTIVE_ROUNDS.set(2);
        VTXOS_CREATED.inc();
        SWEEPS_TOTAL.inc();

        let output = encode_metrics();
        assert!(output.contains("dark_rounds_total"));
        assert!(output.contains("dark_active_rounds 2"));
        assert!(output.contains("dark_vtxos_created_total"));
        assert!(output.contains("dark_sweeps_total"));
    }

    #[test]
    fn test_counter_increments() {
        let before = PARTICIPANTS_TOTAL.get();
        PARTICIPANTS_TOTAL.inc();
        assert_eq!(PARTICIPANTS_TOTAL.get(), before + 1);
    }

    #[test]
    fn test_gauge_set_and_modify() {
        VTXOS_ACTIVE.set(10);
        assert_eq!(VTXOS_ACTIVE.get(), 10);
        VTXOS_ACTIVE.dec();
        assert_eq!(VTXOS_ACTIVE.get(), 9);
    }

    /// Issue #541: ensure the round-variant counters are registered with
    /// the global registry so production scrapes pick them up. Also confirms
    /// they are *plain* `IntCounter`s (no owner-bearing labels) — the metric
    /// must not be exposable as a side channel.
    #[test]
    fn round_variant_counters_registered_and_label_free() {
        // Trigger lazy registration.
        ROUND_CONFIDENTIAL_TX_COUNT.inc_by(2);
        ROUND_TRANSPARENT_TX_COUNT.inc_by(3);

        let output = encode_metrics();
        assert!(
            output.contains("dark_round_confidential_tx_count"),
            "metrics output should expose dark_round_confidential_tx_count: {output}"
        );
        assert!(
            output.contains("dark_round_transparent_tx_count"),
            "metrics output should expose dark_round_transparent_tx_count: {output}"
        );
        // Labels would render as `name{key="..."} value`. The counter has no
        // labels so its emitted line must not contain a `{` between the
        // metric name and the value.
        for line in output.lines() {
            if line.starts_with("dark_round_confidential_tx_count")
                || line.starts_with("dark_round_transparent_tx_count")
            {
                if line.starts_with('#') {
                    continue; // HELP / TYPE comment lines
                }
                assert!(
                    !line.contains('{'),
                    "round-variant counters must not carry labels (got `{line}`)"
                );
            }
        }
    }

    #[test]
    fn test_confidential_validation_error_counter_records_per_reason() {
        let before = confidential_validation_error_total_for("fee_too_low");
        record_confidential_validation_error("fee_too_low");
        record_confidential_validation_error("fee_too_low");
        let after = confidential_validation_error_total_for("fee_too_low");
        assert!(after >= before + 2);
    }

    #[test]
    fn test_confidential_validation_error_appears_in_encoded_metrics() {
        record_confidential_validation_error("invalid_range_proof");
        let output = encode_metrics();
        assert!(output.contains("dark_confidential_validation_error_total"));
        assert!(output.contains("reason=\"invalid_range_proof\""));
    }
}
