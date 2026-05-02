//! End-to-end PSAR demo runner + structured run report (issue #680).
//!
//! [`run_demo`] performs the full PSAR happy-path against an in-process
//! ASP — boarding, every epoch, then signature verification — and
//! returns a [`RunReport`] with the per-phase timings and counts. The
//! `psar-demo` binary in `src/bin/psar-demo.rs` is a thin wrapper that
//! parses CLI flags, calls [`run_demo`], serialises the result to JSON
//! at `--report-path`, and exits.
//!
//! # Schema stability
//!
//! The JSON shape produced by `serde_json::to_string(&RunReport)` is
//! the contract for the benchmark plotter in #687. **The set of keys
//! and `schema_version` constant must stay stable across phase 5/6.**
//! Additive changes (new fields with `#[serde(default)]`) are allowed;
//! key renames or removals require bumping `SCHEMA_VERSION`.
//!
//! # Tracing spans
//!
//! Three `info_span!` instances are emitted per run:
//!
//! - `psar.boarding` — wraps `asp_board`.
//! - `psar.epoch{t}` — one per processed epoch (the `t` field is set
//!   on the span so a `tracing-subscriber` filter can target a single
//!   epoch).
//! - `psar.aggregate` — wraps the final per-user signature
//!   verification pass.

use std::time::Instant;

use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{
    schnorr::Signature, Keypair, Message, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use tracing::{info_span, warn};

use crate::boarding::asp_board;
use crate::cohort::{CohortMember, HibernationHorizon};
use crate::epoch::{process_epoch, EpochArtifacts};
use crate::error::PsarError;
use crate::message::derive_message_for_epoch;
use dark_von_musig2::sign::build_key_agg_ctx;

/// Stable schema marker for [`RunReport`]. Bump on any breaking key
/// rename or removal; #687 reads this when plotting.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunReport {
    pub schema_version: u32,
    pub k: u32,
    pub n: u32,
    pub seed: u64,
    pub boarding: BoardingReport,
    pub epochs: Vec<EpochReport>,
    pub aggregate: AggregateReport,
    pub totals: TotalsReport,
    /// Set when the demo published `SlotAttest` on regtest; `None`
    /// for the default off-chain run.
    pub publish_txid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoardingReport {
    pub duration_ms: u64,
    /// Hex-encoded 32-byte cohort id.
    pub cohort_id: String,
    /// Hex-encoded 32-byte slot Merkle root.
    pub slot_root: String,
    /// Hex-encoded 32-byte batch-tree root.
    pub batch_tree_root: String,
    /// Hex-encoded 32-byte schedule witness (identical across cohort).
    pub schedule_witness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochReport {
    pub t: u32,
    pub duration_ms: u64,
    pub signatures: u32,
    pub failures: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateReport {
    pub duration_ms: u64,
    pub total_signatures: u32,
    pub total_failures: u32,
    pub all_verify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotalsReport {
    pub wall_clock_ms: u64,
}

/// Run the PSAR happy-path end-to-end and return a structured report.
///
/// Generates `K` synthetic users from `seed`, boards them for a
/// horizon of `N` epochs, processes every epoch, and verifies that
/// every per-user 64-byte BIP-340 signature checks out under the
/// 2-of-2 aggregate of `(asp_pk, user_pk)`.
///
/// Errors propagated from `dark-psar` (e.g. setup failure, partial-sig
/// rejection past the eviction threshold) bubble through as
/// [`PsarError`].
pub fn run_demo(k: u32, n: u32, seed: u64) -> Result<RunReport, PsarError> {
    let total_start = Instant::now();
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, seed ^ 0xA5);
    let horizon = HibernationHorizon::new(n, n.max(12))?;
    let members_kps = build_members(&secp, k, seed);
    let cohort_id = cohort_id_for_seed(seed);
    let setup_id = setup_id_for_seed(seed);

    // ─── psar.boarding ────────────────────────────────────────────────
    let boarding = {
        let span = info_span!("psar.boarding", k, n, seed);
        let _g = span.enter();
        let start = Instant::now();
        let mut rng = StdRng::seed_from_u64(seed);
        let active = asp_board(
            &asp_kp,
            cohort_id,
            members_kps,
            horizon,
            setup_id,
            None,
            &mut rng,
        )?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let witness = active
            .artifacts
            .values()
            .next()
            .map(|a| hex::encode(a.schedule_witness))
            .unwrap_or_default();
        let report = BoardingReport {
            duration_ms,
            cohort_id: hex::encode(active.cohort.id),
            slot_root: hex::encode(active.slot_root.as_bytes()),
            batch_tree_root: hex::encode(active.batch_tree_root),
            schedule_witness: witness,
        };
        (active, report)
    };
    let (mut active, boarding_report) = boarding;

    // ─── psar.epoch{t} per epoch ──────────────────────────────────────
    let mut epoch_reports = Vec::with_capacity(n as usize);
    let mut history: Vec<EpochArtifacts> = Vec::with_capacity(n as usize);
    for t in 1..=n {
        let span = info_span!("psar.epoch", t = t);
        let _g = span.enter();
        let start = Instant::now();
        let arts = process_epoch(&mut active, &asp_kp, t)?;
        let duration_ms = start.elapsed().as_millis() as u64;
        epoch_reports.push(EpochReport {
            t,
            duration_ms,
            signatures: arts.signatures.len() as u32,
            failures: arts.failures.len() as u32,
        });
        history.push(arts);
    }

    // ─── psar.aggregate (verification) ────────────────────────────────
    let aggregate_report = {
        let span = info_span!("psar.aggregate");
        let _g = span.enter();
        let start = Instant::now();
        let asp_xonly = asp_kp.x_only_public_key().0;
        let asp_full = lift_xonly_to_even(&asp_xonly);
        let mut total_signatures: u32 = 0;
        let mut total_failures: u32 = 0;
        let mut all_verify = true;
        for (idx, arts) in history.iter().enumerate() {
            let t = (idx + 1) as u32;
            let m_t = derive_message_for_epoch(
                active.slot_root.as_bytes(),
                &active.batch_tree_root,
                t,
                n,
            );
            let msg = Message::from_digest(m_t);
            total_failures += arts.failures.len() as u32;
            for member in &active.cohort.members {
                let Some(sig_bytes) = arts.signatures.get(&member.user_id) else {
                    continue;
                };
                let user_xonly = match XOnlyPublicKey::from_slice(&member.pk_user) {
                    Ok(x) => x,
                    Err(_) => {
                        all_verify = false;
                        warn!(
                            user_id = %hex::encode(member.user_id),
                            "user pk_user failed XOnly parse — counting as verify failure"
                        );
                        continue;
                    }
                };
                let user_full = lift_xonly_to_even(&user_xonly);
                let ctx = match build_key_agg_ctx(&[asp_full, user_full]) {
                    Ok(c) => c,
                    Err(_) => {
                        all_verify = false;
                        continue;
                    }
                };
                let agg_xonly = match XOnlyPublicKey::from_slice(&ctx.x_only_pubkey()) {
                    Ok(x) => x,
                    Err(_) => {
                        all_verify = false;
                        continue;
                    }
                };
                let sig = match Signature::from_slice(sig_bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        all_verify = false;
                        continue;
                    }
                };
                if secp.verify_schnorr(&sig, &msg, &agg_xonly).is_err() {
                    all_verify = false;
                } else {
                    total_signatures += 1;
                }
            }
        }
        AggregateReport {
            duration_ms: start.elapsed().as_millis() as u64,
            total_signatures,
            total_failures,
            all_verify,
        }
    };

    let totals = TotalsReport {
        wall_clock_ms: total_start.elapsed().as_millis() as u64,
    };

    Ok(RunReport {
        schema_version: SCHEMA_VERSION,
        k,
        n,
        seed,
        boarding: boarding_report,
        epochs: epoch_reports,
        aggregate: aggregate_report,
        totals,
        publish_txid: None,
    })
}

// ─── Helpers (deterministic key + member generation) ───────────────────

fn cohort_id_for_seed(seed: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&seed.to_le_bytes());
    id
}

fn setup_id_for_seed(seed: u64) -> [u8; 32] {
    let mut id = [0xc4u8; 32];
    id[..8].copy_from_slice(&seed.to_le_bytes());
    id
}

fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u64) -> Keypair {
    for offset in 0u32..1024 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[28..32].copy_from_slice(&offset.to_le_bytes());
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            let kp = Keypair::from_secret_key(secp, &sk);
            if kp.x_only_public_key().1 == Parity::Even {
                return kp;
            }
        }
    }
    panic!("no even-parity keypair within counter range for seed {seed:#x}")
}

fn build_members(
    secp: &Secp256k1<secp256k1::All>,
    k: u32,
    seed: u64,
) -> Vec<(CohortMember, Keypair)> {
    (0..k)
        .map(|i| {
            let kp = even_parity_keypair(secp, seed.wrapping_add(0x1000_0001 * (i as u64 + 1)));
            let xonly = kp.x_only_public_key().0.serialize();
            let mut user_id = [0u8; 32];
            user_id[0] = ((i >> 8) & 0xff) as u8;
            user_id[1] = (i & 0xff) as u8;
            (
                CohortMember {
                    user_id,
                    pk_user: xonly,
                    slot_index: i,
                },
                kp,
            )
        })
        .collect()
}

fn lift_xonly_to_even(pk: &XOnlyPublicKey) -> PublicKey {
    let xb = pk.serialize();
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&xb);
    PublicKey::from_slice(&compressed).expect("x-only lifts to a valid even-parity point")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_demo_smoke_k4_n2_all_verify() {
        let report = run_demo(4, 2, 0xCAFE_BABE).expect("run_demo");
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.k, 4);
        assert_eq!(report.n, 2);
        assert_eq!(report.epochs.len(), 2);
        for (i, e) in report.epochs.iter().enumerate() {
            assert_eq!(e.t, (i + 1) as u32);
            assert_eq!(e.signatures, 4);
            assert_eq!(e.failures, 0);
        }
        assert!(report.aggregate.all_verify);
        assert_eq!(report.aggregate.total_signatures, 4 * 2);
        assert_eq!(report.aggregate.total_failures, 0);
    }

    #[test]
    fn run_demo_is_deterministic_in_seed() {
        let a = run_demo(3, 2, 7).unwrap();
        let b = run_demo(3, 2, 7).unwrap();
        // Counts and IDs are pinned by the seed.
        assert_eq!(a.boarding.cohort_id, b.boarding.cohort_id);
        assert_eq!(a.boarding.slot_root, b.boarding.slot_root);
        assert_eq!(a.boarding.batch_tree_root, b.boarding.batch_tree_root);
        assert_eq!(a.boarding.schedule_witness, b.boarding.schedule_witness);
        assert_eq!(a.aggregate.total_signatures, b.aggregate.total_signatures);
        assert_eq!(a.aggregate.all_verify, b.aggregate.all_verify);
    }

    #[test]
    fn run_demo_report_round_trips_through_json() {
        let r = run_demo(2, 2, 1).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let back: RunReport = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn run_demo_rejects_zero_n() {
        let err = run_demo(2, 0, 1).unwrap_err();
        assert!(matches!(err, PsarError::HorizonOutOfRange { .. }));
    }
}
