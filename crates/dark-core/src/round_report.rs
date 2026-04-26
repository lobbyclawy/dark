//! Round report \u2014 structured metrics for each Ark round.
//!
//! `RoundReport` captures timing, counts, and outcome data for a single round
//! so it can be logged, exported to OpenTelemetry, or forwarded to alerting.
//!
//! See: <https://github.com/lobbyclawy/dark/issues/245>

use std::time::Instant;
use tracing::info;

use crate::round_batching::RoundVariantCounts;

/// Structured report for a single Ark round.
#[derive(Debug, Clone)]
pub struct RoundReport {
    /// Unique round identifier.
    pub round_id: String,
    /// When the round started.
    pub started_at: Instant,
    /// Duration of the registration phase (ms).
    pub registration_duration_ms: Option<u64>,
    /// Duration of the signing phase (ms).
    pub signing_duration_ms: Option<u64>,
    /// Total round duration (ms), computed by `finish()`.
    pub total_duration_ms: Option<u64>,
    /// Number of intents registered in this round.
    pub intent_count: u32,
    /// Number of VTXOs created.
    pub vtxo_count: u32,
    /// Total sats moved in this round.
    pub total_amount_sats: u64,
    /// Commitment transaction ID (if successfully broadcast).
    pub commitment_txid: Option<String>,
    /// Whether the round failed.
    pub failed: bool,
    /// Human-readable failure reason.
    pub failure_reason: Option<String>,
    /// Per-variant VTXO counts for the round (issue #541).
    ///
    /// Both fields are aggregate counts only — no per-owner data. The
    /// `transparent` and `confidential` totals are emitted as the
    /// `round_transparent_tx_count` and `round_confidential_tx_count`
    /// Prometheus counters from the round-summary path.
    pub variant_counts: RoundVariantCounts,
}

impl Default for RoundReport {
    fn default() -> Self {
        Self {
            round_id: String::new(),
            started_at: Instant::now(),
            registration_duration_ms: None,
            signing_duration_ms: None,
            total_duration_ms: None,
            intent_count: 0,
            vtxo_count: 0,
            total_amount_sats: 0,
            commitment_txid: None,
            failed: false,
            failure_reason: None,
            variant_counts: RoundVariantCounts::default(),
        }
    }
}

impl RoundReport {
    /// Create a new report for the given round ID. Starts the clock.
    pub fn new(round_id: &str) -> Self {
        Self {
            round_id: round_id.to_string(),
            started_at: Instant::now(),
            ..Default::default()
        }
    }

    /// Mark the round as finished and compute `total_duration_ms`.
    pub fn finish(&mut self) {
        self.total_duration_ms = Some(self.started_at.elapsed().as_millis() as u64);
    }

    /// Mark the round as failed with a reason.
    pub fn fail(&mut self, reason: &str) {
        self.failed = true;
        self.failure_reason = Some(reason.to_string());
        self.finish();
    }

    /// Record per-variant VTXO counts for the round and emit the
    /// `round_transparent_tx_count` / `round_confidential_tx_count`
    /// Prometheus counters (issue #541).
    ///
    /// Counts are *added* to the cumulative metric counters via `inc_by`, so
    /// per-round deltas are recoverable on the consumer side. The internal
    /// [`RoundReport::variant_counts`] field is also updated so the structured
    /// log line includes the per-variant counts at completion time.
    ///
    /// Idempotent on the in-memory field (overwrites), but each call also
    /// adds to the cumulative counter — so call this exactly once per round.
    pub fn record_variant_counts(&mut self, counts: RoundVariantCounts) {
        self.variant_counts = counts;
        crate::metrics::ROUND_TRANSPARENT_TX_COUNT.inc_by(u64::from(counts.transparent));
        crate::metrics::ROUND_CONFIDENTIAL_TX_COUNT.inc_by(u64::from(counts.confidential));
    }

    /// Log a structured summary via `tracing::info!` (or `warn!` on failure).
    pub fn log_summary(&self) {
        if self.failed {
            tracing::warn!(
                round_id = %self.round_id,
                total_duration_ms = ?self.total_duration_ms,
                registration_duration_ms = ?self.registration_duration_ms,
                signing_duration_ms = ?self.signing_duration_ms,
                intent_count = self.intent_count,
                vtxo_count = self.vtxo_count,
                total_amount_sats = self.total_amount_sats,
                commitment_txid = ?self.commitment_txid,
                failure_reason = ?self.failure_reason,
                round_transparent_tx_count = self.variant_counts.transparent,
                round_confidential_tx_count = self.variant_counts.confidential,
                "Round FAILED"
            );
        } else {
            info!(
                round_id = %self.round_id,
                total_duration_ms = ?self.total_duration_ms,
                registration_duration_ms = ?self.registration_duration_ms,
                signing_duration_ms = ?self.signing_duration_ms,
                intent_count = self.intent_count,
                vtxo_count = self.vtxo_count,
                total_amount_sats = self.total_amount_sats,
                commitment_txid = ?self.commitment_txid,
                round_transparent_tx_count = self.variant_counts.transparent,
                round_confidential_tx_count = self.variant_counts.confidential,
                "Round completed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_round_report_new() {
        let report = RoundReport::new("round-001");
        assert_eq!(report.round_id, "round-001");
        assert!(!report.failed);
        assert!(report.total_duration_ms.is_none());
    }

    #[test]
    fn test_round_report_finish_computes_duration() {
        let mut report = RoundReport::new("round-002");
        sleep(Duration::from_millis(10));
        report.finish();
        assert!(report.total_duration_ms.is_some());
        assert!(report.total_duration_ms.unwrap() >= 10);
    }

    #[test]
    fn test_round_report_fail() {
        let mut report = RoundReport::new("round-003");
        report.fail("signing timeout");
        assert!(report.failed);
        assert_eq!(report.failure_reason.as_deref(), Some("signing timeout"));
        assert!(report.total_duration_ms.is_some());
    }

    #[test]
    fn test_round_report_default() {
        let report = RoundReport::default();
        assert!(report.round_id.is_empty());
        assert!(!report.failed);
        assert_eq!(report.variant_counts, RoundVariantCounts::default());
    }

    /// Issue #541: `record_variant_counts` populates the in-memory field and
    /// also bumps the cumulative Prometheus counters so per-round deltas are
    /// recoverable from a metrics scrape.
    #[test]
    fn test_round_report_record_variant_counts() {
        let mut report = RoundReport::new("round-counts");
        let before_t = crate::metrics::ROUND_TRANSPARENT_TX_COUNT.get();
        let before_c = crate::metrics::ROUND_CONFIDENTIAL_TX_COUNT.get();

        report.record_variant_counts(RoundVariantCounts {
            transparent: 3,
            confidential: 2,
        });

        // In-memory field updated.
        assert_eq!(report.variant_counts.transparent, 3);
        assert_eq!(report.variant_counts.confidential, 2);

        // Counters incremented by the per-round delta.
        assert_eq!(
            crate::metrics::ROUND_TRANSPARENT_TX_COUNT.get(),
            before_t + 3
        );
        assert_eq!(
            crate::metrics::ROUND_CONFIDENTIAL_TX_COUNT.get(),
            before_c + 2
        );
    }
}
