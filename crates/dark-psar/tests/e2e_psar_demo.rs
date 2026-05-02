//! End-to-end test for the `psar-demo` runner (issue #680).
//!
//! Exercises [`dark_psar::run_demo`] directly so the test runs under
//! the default `cargo test --workspace` invocation (no `--features
//! demo` required). The binary wrapper in `src/bin/psar-demo.rs` is
//! covered by manual smoke per `docs/sdk/psar.md`; this test pins the
//! runner's contract.

use dark_psar::{run_demo, RunReport, SCHEMA_VERSION};

#[test]
fn run_demo_smoke_k10_n4_yields_full_horizon_of_renewals() {
    let report = run_demo(10, 4, 0xDE5C_DA7A_5EED_2026).expect("run_demo");

    // Schema invariants — frozen for #687.
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.k, 10);
    assert_eq!(report.n, 4);

    // One epoch report per epoch, in order.
    assert_eq!(report.epochs.len(), 4);
    for (i, e) in report.epochs.iter().enumerate() {
        assert_eq!(e.t, (i + 1) as u32);
        assert_eq!(e.signatures, 10);
        assert_eq!(e.failures, 0);
    }

    // K × N = 40 renewal signatures, all of which must verify under
    // the 2-of-2 BIP-340 aggregate of (asp, user) for each epoch.
    assert!(report.aggregate.all_verify, "all renewal sigs must verify");
    assert_eq!(report.aggregate.total_signatures, 10 * 4);
    assert_eq!(report.aggregate.total_failures, 0);

    // Boarding fields are 32-byte hex (64 chars).
    assert_eq!(report.boarding.cohort_id.len(), 64);
    assert_eq!(report.boarding.slot_root.len(), 64);
    assert_eq!(report.boarding.batch_tree_root.len(), 64);
    assert_eq!(report.boarding.schedule_witness.len(), 64);

    // No regtest publish in the in-process demo.
    assert!(report.publish_txid.is_none());
}

#[test]
fn run_demo_report_round_trips_through_json() {
    let r = run_demo(4, 2, 1234).unwrap();
    let s = serde_json::to_string(&r).expect("serialise");
    let back: RunReport = serde_json::from_str(&s).expect("deserialise");
    assert_eq!(r, back);
}

#[test]
fn run_demo_seed_pins_observable_outputs() {
    // The plotter in #687 will re-run identical (k, n, seed) tuples
    // across machines and expect bit-stable boarding outputs.
    let a = run_demo(4, 2, 0xC0FFEE).unwrap();
    let b = run_demo(4, 2, 0xC0FFEE).unwrap();
    assert_eq!(a.boarding.cohort_id, b.boarding.cohort_id);
    assert_eq!(a.boarding.slot_root, b.boarding.slot_root);
    assert_eq!(a.boarding.batch_tree_root, b.boarding.batch_tree_root);
    assert_eq!(a.boarding.schedule_witness, b.boarding.schedule_witness);
}
