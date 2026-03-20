//! Round report \u2014 structured metrics for each Ark round.
//!
//! `RoundReport` captures timing, counts, and outcome data for a single round
//! so it can be logged, exported to OpenTelemetry, or forwarded to alerting.
//!
//! See: <https://github.com/lobbyclawy/dark/issues/245>

use std::time::Instant;
use tracing::info;

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
    }
}
