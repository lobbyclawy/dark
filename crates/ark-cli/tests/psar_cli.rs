//! Integration tests for `ark-cli psar` (issue #679).
//!
//! These tests invoke the built `ark-cli` binary as a subprocess and
//! assert that each subcommand exits 0 and emits a parseable JSON line
//! with the documented schema. The schema is the contract for the
//! `psar-demo` binary in #680, so it must stay stable.

use std::process::Command;

use serde::Deserialize;
use serde_json::Value;

fn ark_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ark-cli"))
}

#[derive(Debug, Deserialize)]
struct BoardOut {
    kind: String,
    cohort_id: String,
    k: u32,
    n: u32,
    slot_root: String,
    batch_tree_root: String,
    schedule_witness: String,
    members: usize,
}

#[derive(Debug, Deserialize)]
struct EpochSummary {
    t: u32,
    signatures: usize,
    failures: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Fields are decoded to validate the JSON schema, not all are asserted on.
struct AdvanceEpochOut {
    kind: String,
    cohort_id: String,
    k: u32,
    n: u32,
    through_epoch: u32,
    epochs: Vec<EpochSummary>,
    final_state: String,
}

#[derive(Debug, Deserialize)]
struct ResurfaceOut {
    kind: String,
    cohort_id: String,
    slot_index: u32,
    t_prime: u32,
    renewal_sig: String,
    renewal_msg: String,
}

fn run_for_json(args: &[&str]) -> Value {
    let out = ark_cli()
        .args(args)
        .output()
        .expect("failed to spawn ark-cli");
    assert!(
        out.status.success(),
        "ark-cli {args:?} exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let line = String::from_utf8(out.stdout).expect("stdout is utf-8");
    serde_json::from_str(line.trim()).expect("stdout is one JSON line")
}

#[test]
fn psar_help_lists_three_subcommands() {
    let out = ark_cli().args(["psar", "--help"]).output().expect("spawn");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["board", "advance-epoch", "resurface"] {
        assert!(
            stdout.contains(sub),
            "psar --help missing subcommand `{sub}`"
        );
    }
}

#[test]
fn board_emits_well_formed_json_line() {
    let v = run_for_json(&["psar", "board", "--k", "4", "--n", "2"]);
    let parsed: BoardOut = serde_json::from_value(v).unwrap();
    assert_eq!(parsed.kind, "board");
    assert_eq!(parsed.k, 4);
    assert_eq!(parsed.n, 2);
    assert_eq!(parsed.members, 4);
    assert_eq!(parsed.cohort_id.len(), 64); // 32 bytes hex
    assert_eq!(parsed.slot_root.len(), 64);
    assert_eq!(parsed.batch_tree_root.len(), 64);
    assert_eq!(parsed.schedule_witness.len(), 64);
}

#[test]
fn advance_epoch_emits_per_epoch_summary() {
    let v = run_for_json(&[
        "psar",
        "advance-epoch",
        "--k",
        "3",
        "--n",
        "2",
        "--through-epoch",
        "2",
    ]);
    let parsed: AdvanceEpochOut = serde_json::from_value(v).unwrap();
    assert_eq!(parsed.kind, "advance-epoch");
    assert_eq!(parsed.k, 3);
    assert_eq!(parsed.n, 2);
    assert_eq!(parsed.through_epoch, 2);
    assert_eq!(parsed.epochs.len(), 2);
    for (i, e) in parsed.epochs.iter().enumerate() {
        assert_eq!(e.t, (i + 1) as u32);
        assert_eq!(e.signatures, 3);
        assert_eq!(e.failures, 0);
    }
    // Through the full horizon → Concluded.
    assert_eq!(parsed.final_state, "Concluded");
}

#[test]
fn advance_epoch_rejects_out_of_range_through_epoch() {
    let out = ark_cli()
        .args([
            "psar",
            "advance-epoch",
            "--k",
            "2",
            "--n",
            "2",
            "--through-epoch",
            "9",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected non-zero exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("through-epoch") || stderr.contains("out of range"),
        "stderr did not mention range violation:\n{stderr}"
    );
}

#[test]
fn resurface_emits_renewal_sig_and_msg() {
    let v = run_for_json(&[
        "psar",
        "resurface",
        "--k",
        "4",
        "--n",
        "2",
        "--slot-index",
        "1",
        "--epoch",
        "1",
    ]);
    let parsed: ResurfaceOut = serde_json::from_value(v).unwrap();
    assert_eq!(parsed.kind, "resurface");
    assert_eq!(parsed.slot_index, 1);
    assert_eq!(parsed.t_prime, 1);
    assert_eq!(parsed.cohort_id.len(), 64);
    assert_eq!(parsed.renewal_sig.len(), 128); // 64 bytes hex
    assert_eq!(parsed.renewal_msg.len(), 64); // 32 bytes hex
}

#[test]
fn resurface_rejects_out_of_range_slot() {
    let out = ark_cli()
        .args([
            "psar",
            "resurface",
            "--k",
            "2",
            "--n",
            "2",
            "--slot-index",
            "5",
            "--epoch",
            "1",
        ])
        .output()
        .expect("spawn");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("slot-index") || stderr.contains("out of range"),
        "stderr did not mention range violation:\n{stderr}"
    );
}

#[test]
fn board_is_deterministic_in_seed() {
    // Same seed → same cohort_id, slot_root, batch_tree_root.
    let a = run_for_json(&["psar", "board", "--k", "3", "--n", "2", "--seed", "42"]);
    let b = run_for_json(&["psar", "board", "--k", "3", "--n", "2", "--seed", "42"]);
    assert_eq!(a["cohort_id"], b["cohort_id"]);
    assert_eq!(a["slot_root"], b["slot_root"]);
    assert_eq!(a["batch_tree_root"], b["batch_tree_root"]);
    assert_eq!(a["schedule_witness"], b["schedule_witness"]);
}
