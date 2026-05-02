//! `ark-cli psar` subcommands (issue #679).
//!
//! These wrap [`dark_psar`] calls so the demo binary in #680 can be
//! scripted from shell. Each subcommand is *self-contained*: it
//! generates the K user keypairs in-process from a deterministic seed,
//! runs the corresponding dark-psar call, and emits a single JSON line
//! to stdout describing the outcome.
//!
//! The JSON line is the contract — `crates/ark-cli/tests/psar_cli.rs`
//! parses it back, and #680's `psar-demo` will too. Keys must remain
//! stable across phase 5/6.
//!
//! ## Subcommands
//!
//! - `board --k K --n N --setup-id <hex32> [--seed <u64>]` — runs
//!   [`dark_psar::asp_board`] for a fresh cohort of `K` synthetic users
//!   over a horizon of `N` epochs and prints `{ kind: "board", … }`.
//! - `advance-epoch --k K --n N --setup-id <hex32> --through-epoch t
//!   [--seed <u64>]` — boards then drives [`dark_psar::process_epoch`]
//!   for `t = 1..=through_epoch`, prints `{ kind: "advance-epoch", … }`.
//! - `resurface --k K --n N --setup-id <hex32> --slot-index s
//!   --epoch t [--seed <u64>]` — boards, advances through epoch `t`,
//!   then [`dark_psar::user_resurface`]s slot `s` at `t_prime = t`,
//!   prints `{ kind: "resurface", … }`.

use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{Keypair, Parity, Secp256k1, SecretKey};
use serde::Serialize;

use dark_psar::{
    asp_board, process_epoch, user_resurface, CohortMember, EpochArtifacts, HibernationHorizon,
};

/// Default RNG seed when `--seed` is not provided. Pinned so the
/// integration test in `tests/psar_cli.rs` and the demo in #680 see
/// reproducible output.
const DEFAULT_SEED: u64 = 0xDA4C_50A4_5EED_2026;

/// Default 32-byte setup id used when `--setup-id` is omitted (all
/// `0xc4` for visual obviousness).
const DEFAULT_SETUP_ID_HEX: &str =
    "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

#[derive(Subcommand, Debug, Clone)]
pub enum PsarAction {
    /// Run ASP-side boarding for a fresh cohort and print a JSON line.
    Board(BoardArgs),
    /// Board, then advance through the first `t` epochs.
    AdvanceEpoch(AdvanceEpochArgs),
    /// Board, advance through epoch `t`, then resurface a user.
    Resurface(ResurfaceArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct BoardArgs {
    /// Cohort size (number of synthetic users).
    #[arg(long, default_value = "4")]
    pub k: u32,
    /// Hibernation horizon (number of epochs).
    #[arg(long, default_value = "2")]
    pub n: u32,
    /// 32-byte setup id, hex-encoded (64 lowercase hex chars).
    #[arg(long, default_value = DEFAULT_SETUP_ID_HEX)]
    pub setup_id: String,
    /// RNG seed for deterministic keypair generation.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
}

#[derive(clap::Args, Debug, Clone)]
pub struct AdvanceEpochArgs {
    #[arg(long, default_value = "4")]
    pub k: u32,
    #[arg(long, default_value = "2")]
    pub n: u32,
    #[arg(long, default_value = DEFAULT_SETUP_ID_HEX)]
    pub setup_id: String,
    /// Drive epochs `1..=through_epoch`. Must be in `[1, n]`.
    #[arg(long)]
    pub through_epoch: u32,
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
}

#[derive(clap::Args, Debug, Clone)]
pub struct ResurfaceArgs {
    #[arg(long, default_value = "4")]
    pub k: u32,
    #[arg(long, default_value = "2")]
    pub n: u32,
    #[arg(long, default_value = DEFAULT_SETUP_ID_HEX)]
    pub setup_id: String,
    /// Slot index of the resurfacing user (`0 ≤ slot_index < k`).
    #[arg(long)]
    pub slot_index: u32,
    /// Epoch at which to resurface. Must satisfy `1 ≤ epoch ≤ n` and
    /// `≤` the number of epochs that have actually been processed.
    #[arg(long)]
    pub epoch: u32,
    #[arg(long, default_value_t = DEFAULT_SEED)]
    pub seed: u64,
}

pub fn handle(action: PsarAction) -> Result<()> {
    match action {
        PsarAction::Board(args) => board(args),
        PsarAction::AdvanceEpoch(args) => advance_epoch(args),
        PsarAction::Resurface(args) => resurface(args),
    }
}

// ─── Subcommand handlers ───────────────────────────────────────────────

#[derive(Serialize)]
struct BoardOut {
    kind: &'static str,
    cohort_id: String,
    k: u32,
    n: u32,
    slot_root: String,
    batch_tree_root: String,
    schedule_witness: String,
    members: usize,
}

fn board(args: BoardArgs) -> Result<()> {
    let setup_id = parse_setup_id(&args.setup_id)?;
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, args.seed ^ 0xA5);
    let horizon = HibernationHorizon::new(args.n, args.n.max(12))
        .map_err(|e| anyhow!("invalid horizon: {e}"))?;
    let members_kps = build_members(&secp, args.k, args.seed);
    let cohort_id = cohort_id_for_seed(args.seed);
    let mut rng = StdRng::seed_from_u64(args.seed);
    let active = asp_board(
        &asp_kp,
        cohort_id,
        members_kps,
        horizon,
        setup_id,
        None,
        &mut rng,
    )
    .map_err(|e| anyhow!("asp_board failed: {e}"))?;

    let witness = active
        .artifacts
        .values()
        .next()
        .map(|a| hex::encode(a.schedule_witness))
        .unwrap_or_default();
    let out = BoardOut {
        kind: "board",
        cohort_id: hex::encode(active.cohort.id),
        k: active.cohort.k(),
        n: active.cohort.horizon.n,
        slot_root: hex::encode(active.slot_root.as_bytes()),
        batch_tree_root: hex::encode(active.batch_tree_root),
        schedule_witness: witness,
        members: active.artifacts.len(),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[derive(Serialize)]
struct EpochSummary {
    t: u32,
    signatures: usize,
    failures: usize,
}

#[derive(Serialize)]
struct AdvanceEpochOut {
    kind: &'static str,
    cohort_id: String,
    k: u32,
    n: u32,
    through_epoch: u32,
    epochs: Vec<EpochSummary>,
    final_state: &'static str,
}

fn advance_epoch(args: AdvanceEpochArgs) -> Result<()> {
    if args.through_epoch == 0 || args.through_epoch > args.n {
        return Err(anyhow!(
            "--through-epoch {} out of range [1, {}]",
            args.through_epoch,
            args.n
        ));
    }
    let setup_id = parse_setup_id(&args.setup_id)?;
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, args.seed ^ 0xA5);
    let horizon = HibernationHorizon::new(args.n, args.n.max(12))
        .map_err(|e| anyhow!("invalid horizon: {e}"))?;
    let members_kps = build_members(&secp, args.k, args.seed);
    let cohort_id = cohort_id_for_seed(args.seed);
    let mut rng = StdRng::seed_from_u64(args.seed);
    let mut active = asp_board(
        &asp_kp,
        cohort_id,
        members_kps,
        horizon,
        setup_id,
        None,
        &mut rng,
    )
    .map_err(|e| anyhow!("asp_board failed: {e}"))?;

    let mut epochs = Vec::with_capacity(args.through_epoch as usize);
    for t in 1..=args.through_epoch {
        let arts: EpochArtifacts =
            process_epoch(&mut active, &asp_kp, t).map_err(|e| anyhow!("process_epoch: {e}"))?;
        epochs.push(EpochSummary {
            t,
            signatures: arts.signatures.len(),
            failures: arts.failures.len(),
        });
    }
    let final_state = state_label(active.cohort.state());
    let out = AdvanceEpochOut {
        kind: "advance-epoch",
        cohort_id: hex::encode(active.cohort.id),
        k: active.cohort.k(),
        n: active.cohort.horizon.n,
        through_epoch: args.through_epoch,
        epochs,
        final_state,
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

#[derive(Serialize)]
struct ResurfaceOut {
    kind: &'static str,
    cohort_id: String,
    slot_index: u32,
    t_prime: u32,
    renewal_sig: String,
    renewal_msg: String,
}

fn resurface(args: ResurfaceArgs) -> Result<()> {
    if args.slot_index >= args.k {
        return Err(anyhow!(
            "--slot-index {} out of range [0, {})",
            args.slot_index,
            args.k
        ));
    }
    if args.epoch == 0 || args.epoch > args.n {
        return Err(anyhow!(
            "--epoch {} out of range [1, {}]",
            args.epoch,
            args.n
        ));
    }
    let setup_id = parse_setup_id(&args.setup_id)?;
    let secp = Secp256k1::new();
    let asp_kp = even_parity_keypair(&secp, args.seed ^ 0xA5);
    let horizon = HibernationHorizon::new(args.n, args.n.max(12))
        .map_err(|e| anyhow!("invalid horizon: {e}"))?;
    let members_kps = build_members(&secp, args.k, args.seed);
    let user_kp = members_kps[args.slot_index as usize].1;
    let cohort_id = cohort_id_for_seed(args.seed);
    let mut rng = StdRng::seed_from_u64(args.seed);
    let mut active = asp_board(
        &asp_kp,
        cohort_id,
        members_kps,
        horizon,
        setup_id,
        None,
        &mut rng,
    )
    .map_err(|e| anyhow!("asp_board failed: {e}"))?;

    let mut history = Vec::with_capacity(args.epoch as usize);
    for t in 1..=args.epoch {
        history.push(
            process_epoch(&mut active, &asp_kp, t).map_err(|e| anyhow!("process_epoch: {e}"))?,
        );
    }

    let artifact = user_resurface(&active, &history, &user_kp, args.slot_index, args.epoch)
        .map_err(|e| anyhow!("user_resurface: {e}"))?;
    let out = ResurfaceOut {
        kind: "resurface",
        cohort_id: hex::encode(active.cohort.id),
        slot_index: artifact.slot_index,
        t_prime: artifact.t_prime,
        renewal_sig: hex::encode(artifact.renewal_sig_at_t_prime),
        renewal_msg: hex::encode(artifact.renewal_msg_at_t_prime),
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}

// ─── Helpers ───────────────────────────────────────────────────────────

fn parse_setup_id(hex: &str) -> Result<[u8; 32]> {
    let bytes = ::hex::decode(hex).context("--setup-id must be valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "--setup-id must decode to 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn cohort_id_for_seed(seed: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
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
            // Mix the user index into the seed so each slot gets a
            // distinct keypair while staying deterministic in (seed, k).
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

fn state_label(s: dark_psar::CohortState) -> &'static str {
    use dark_psar::CohortState::*;
    match s {
        Forming => "Forming",
        Committed => "Committed",
        Active => "Active",
        InProgress(_) => "InProgress",
        Concluded => "Concluded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_setup_id() -> String {
        DEFAULT_SETUP_ID_HEX.to_string()
    }

    #[test]
    fn parse_setup_id_accepts_64_lowercase_hex() {
        let id = parse_setup_id(&default_setup_id()).unwrap();
        assert_eq!(id, [0xc4u8; 32]);
    }

    #[test]
    fn parse_setup_id_rejects_wrong_length() {
        let err = parse_setup_id("c4c4").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn parse_setup_id_rejects_non_hex() {
        let err = parse_setup_id("xxxx").unwrap_err();
        assert!(err.to_string().contains("valid hex"));
    }

    #[test]
    fn build_members_is_deterministic_in_seed_and_k() {
        let secp = Secp256k1::new();
        let a = build_members(&secp, 4, 1234);
        let b = build_members(&secp, 4, 1234);
        for (m_a, m_b) in a.iter().zip(b.iter()) {
            assert_eq!(m_a.0.user_id, m_b.0.user_id);
            assert_eq!(m_a.0.pk_user, m_b.0.pk_user);
            assert_eq!(m_a.0.slot_index, m_b.0.slot_index);
        }
    }

    #[test]
    fn build_members_distinct_keys_per_slot() {
        let secp = Secp256k1::new();
        let m = build_members(&secp, 4, 99);
        let mut keys: Vec<_> = m.iter().map(|(c, _)| c.pk_user).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 4, "slots must have distinct user pubkeys");
    }
}
