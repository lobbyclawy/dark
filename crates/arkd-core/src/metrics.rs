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
//! use arkd_core::metrics;
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
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

/// Global metrics registry for arkd.
pub static REGISTRY: Lazy<Registry> = Lazy::new(|| {
    let registry = Registry::new_custom(Some("arkd".to_string()), None)
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
    ];
    let gauges: Vec<&IntGauge> = vec![&ACTIVE_ROUNDS, &ACTIVE_PARTICIPANTS, &VTXOS_ACTIVE];

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
        assert!(output.contains("arkd_rounds_total"));
        assert!(output.contains("arkd_active_rounds 2"));
        assert!(output.contains("arkd_vtxos_created_total"));
        assert!(output.contains("arkd_sweeps_total"));
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
}
