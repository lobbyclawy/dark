//! Boarding flows (issues #670 user-side and #671 ASP-side).
//!
//! This module owns the *coordination* between the `cohort`, `attest`,
//! and `slot_tree` modules and the cryptographic primitives in
//! `dark_von_musig2`. The user-side flow is `user_board` (#670); the
//! ASP-side flow `asp_board` (#671) lives later in this file.
//!
//! # Conventions
//!
//! - Every cohort member's `pk_user` is a 32-byte BIP-340 x-only
//!   public key with **assumed even parity**. Keypairs that yield
//!   odd parity (`secp256k1::Keypair::x_only_public_key().1 ==
//!   Parity::Odd`) are rejected with [`PsarError::OddParity`]; the
//!   caller must negate the secret to renormalize.
//! - The ASP's signing key plays two roles: it signs [`SlotAttest`]
//!   with `Schnorr` (BIP-340) and it acts as the operator in the
//!   VON-MuSig2 protocol. Both consume the same x-only pubkey `pk_asp`,
//!   lifted internally to its even-parity compressed form for
//!   `dark_von_musig2::sign::build_key_agg_ctx`.
//!
//! # Schedule witness
//!
//! `UserBoardingArtifact::schedule_witness` is a hash-chain commitment
//! over Λ:
//!
//! ```text
//! h_0    = SHA256(b"DarkPsarLambdaWitnessV1" || setup_id || n_LE_u32)
//! h_t    = SHA256(h_{t-1} || R_{t,1} || π_{t,1} || R_{t,2} || π_{t,2})
//! witness = h_n
//! ```
//!
//! The chain is deterministic in Λ — the ASP can recompute it at
//! collection time (#671) to verify the user actually consumed the
//! published schedule. Tampering with any byte of any Λ entry yields
//! a different `witness`.

use dark_von_musig2::nonces::PubNonce;
use dark_von_musig2::presign::{presign_horizon, PreSigned};
use dark_von_musig2::setup::PublishedSchedule;
use dark_von_musig2::sign::{build_key_agg_ctx, PartialSignature};
use rand::Rng;
use secp256k1::{Keypair, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::attest::{SlotAttest, SlotAttestUnsigned};
use crate::cohort::Cohort;
use crate::error::PsarError;
use crate::message::derive_message_for_epoch;
use crate::slot_tree::SlotRoot;

/// Tag for the schedule-witness hash chain.
pub const SCHEDULE_WITNESS_TAG: &[u8] = b"DarkPsarLambdaWitnessV1";

/// Per-user boarding output handed back to the ASP for collection.
#[derive(Clone, Debug)]
pub struct UserBoardingArtifact {
    pub slot_index: u32,
    pub n: u32,
    /// Per-epoch pre-signed material; `presigned[t-1]` covers epoch `t`.
    pub presigned: Vec<PreSigned>,
    /// Hash-chain commitment proving the user verified Λ; see module docs.
    pub schedule_witness: [u8; 32],
}

impl UserBoardingArtifact {
    /// Decompose into the parallel `(pub_nonce, partial_sig)` lists the
    /// ASP-side flow keeps in `ActiveCohort`.
    pub fn split(&self) -> (Vec<PubNonce>, Vec<PartialSignature>) {
        let nonces = self.presigned.iter().map(|p| p.pub_nonce.clone()).collect();
        let sigs = self.presigned.iter().map(|p| p.partial_sig).collect();
        (nonces, sigs)
    }
}

/// User-side boarding (#670).
///
/// Given the cohort, the on-chain [`SlotAttest`] (verified against the
/// ASP's BIP-340 pubkey), the published Λ, and the user's keypair:
///
/// 1. Verify `attest` against `pk_asp` and check it agrees with the
///    cohort metadata (`n`, `k`, `cohort_id`).
/// 2. Recompute the slot root over `cohort.members` and check it
///    matches `attest.unsigned.slot_root`.
/// 3. Verify `cohort.members[slot_index].pk_user` matches the
///    keypair's x-only pubkey (and parity is even).
/// 4. Verify every entry of Λ via `dark_von::wrapper::verify`,
///    surfacing the offending `(epoch, slot)` if any fails.
/// 5. Derive `m_t = derive_message_for_epoch(slot_root,
///    batch_tree_root, t, n)` for `t ∈ [1, n]`.
/// 6. Pre-sign the horizon via
///    `dark_von_musig2::presign::presign_horizon` (`presign_horizon`
///    re-verifies Λ — the explicit pre-check above is what produces
///    the `(epoch, slot)`-tagged error).
/// 7. Return [`UserBoardingArtifact`] with the pre-signed material and
///    the schedule witness.
#[allow(clippy::too_many_arguments)] // 8 params is the boarding contract; phase 5 may collapse into a builder.
pub fn user_board<R: Rng + ?Sized>(
    cohort: &Cohort,
    attest: &SlotAttest,
    pk_asp: &XOnlyPublicKey,
    schedule: &PublishedSchedule,
    user_kp: &Keypair,
    slot_index: u32,
    batch_tree_root: [u8; 32],
    rng: &mut R,
) -> Result<UserBoardingArtifact, PsarError> {
    // ─── Cohort / attestation / horizon agreement ────────────────────
    if attest.unsigned.cohort_id != cohort.id {
        return Err(PsarError::AttestationFieldMismatch {
            field: "cohort_id",
            attest_value: 0,
            cohort_value: 0,
        });
    }
    if attest.unsigned.n != cohort.horizon.n {
        return Err(PsarError::AttestationFieldMismatch {
            field: "n",
            attest_value: attest.unsigned.n,
            cohort_value: cohort.horizon.n,
        });
    }
    if attest.unsigned.k != cohort.k() {
        return Err(PsarError::AttestationFieldMismatch {
            field: "k",
            attest_value: attest.unsigned.k,
            cohort_value: cohort.k(),
        });
    }
    if schedule.n != cohort.horizon.n {
        return Err(PsarError::HorizonDisagrees {
            schedule_n: schedule.n,
            cohort_n: cohort.horizon.n,
        });
    }
    let mut setup_id = [0u8; 32];
    if schedule.setup_id.len() != 32 {
        return Err(PsarError::AttestationFieldMismatch {
            field: "setup_id_length",
            attest_value: schedule.setup_id.len() as u32,
            cohort_value: 32,
        });
    }
    setup_id.copy_from_slice(&schedule.setup_id);
    if attest.unsigned.setup_id != setup_id {
        return Err(PsarError::AttestationFieldMismatch {
            field: "setup_id",
            attest_value: 0,
            cohort_value: 0,
        });
    }

    // ─── Attestation signature ────────────────────────────────────────
    attest
        .verify(pk_asp)
        .map_err(|_| PsarError::AttestationVerify)?;

    // ─── Slot-root recomputation ──────────────────────────────────────
    let recomputed = SlotRoot::compute(&cohort.members);
    if recomputed.0 != attest.unsigned.slot_root {
        return Err(PsarError::SlotRootMismatch);
    }

    // ─── Slot membership / pubkey match ───────────────────────────────
    let member = cohort
        .members
        .get(slot_index as usize)
        .ok_or(PsarError::SlotIndexOutOfRange {
            slot_index,
            k: cohort.k(),
        })?;
    if member.slot_index != slot_index {
        return Err(PsarError::SlotIndexOutOfRange {
            slot_index,
            k: cohort.k(),
        });
    }
    let (user_xonly, parity) = user_kp.x_only_public_key();
    if parity == Parity::Odd {
        return Err(PsarError::OddParity);
    }
    if user_xonly.serialize() != member.pk_user {
        return Err(PsarError::PubkeyMismatch { slot_index });
    }

    // ─── Λ pre-verification with (epoch, slot) reporting ──────────────
    verify_lambda_entries(pk_asp, schedule, &setup_id)?;

    // ─── KeyAggCtx + messages + presign ───────────────────────────────
    let pk_asp_full = lift_xonly_to_even(pk_asp);
    let pk_user_full = user_kp.public_key();
    let ctx = build_key_agg_ctx(&[pk_asp_full, pk_user_full])
        .map_err(|e| PsarError::VonMusig2(dark_von_musig2::VonMusig2Error::Bip327(e)))?;

    let messages: Vec<[u8; 32]> = (1..=schedule.n)
        .map(|t| {
            derive_message_for_epoch(&attest.unsigned.slot_root, &batch_tree_root, t, schedule.n)
        })
        .collect();

    let user_sk = SecretKey::from_keypair(user_kp);
    let presigned = presign_horizon(&user_sk, &pk_asp_full, &ctx, schedule, &messages, rng)?;

    // ─── Schedule witness ─────────────────────────────────────────────
    let schedule_witness = compute_schedule_witness(schedule);

    Ok(UserBoardingArtifact {
        slot_index,
        n: schedule.n,
        presigned,
        schedule_witness,
    })
}

/// Pre-flight verification of every `(epoch, slot)` pair in Λ.
///
/// `presign_horizon` already runs the same check, but it surfaces a
/// generic `VonMusig2Error::DarkVon` without the offending coordinates.
/// Doing it here lets the user (and the test in #670) see exactly which
/// entry is broken.
fn verify_lambda_entries(
    pk_asp: &XOnlyPublicKey,
    schedule: &PublishedSchedule,
    setup_id: &[u8; 32],
) -> Result<(), PsarError> {
    let pk_asp_full = lift_xonly_to_even(pk_asp);
    let public = schedule.to_dark_von()?;
    for t in 1..=public.n {
        for b in [1u8, 2u8] {
            let entry = public
                .entry(t, b)
                .ok_or(PsarError::ScheduleInvalid { epoch: t, slot: b })?;
            let x = dark_von::hash::h_nonce(setup_id, t, b);
            dark_von::wrapper::verify(&pk_asp_full, &x, &entry.r_point, &entry.proof)
                .map_err(|_| PsarError::ScheduleInvalid { epoch: t, slot: b })?;
        }
    }
    Ok(())
}

fn lift_xonly_to_even(pk: &XOnlyPublicKey) -> PublicKey {
    let xb = pk.serialize();
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&xb);
    PublicKey::from_slice(&compressed).expect("x-only lifts to a valid even-parity point")
}

fn compute_schedule_witness(schedule: &PublishedSchedule) -> [u8; 32] {
    let mut acc: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(SCHEDULE_WITNESS_TAG);
        h.update(&schedule.setup_id);
        h.update(schedule.n.to_le_bytes());
        h.finalize().into()
    };
    for entry in &schedule.entries {
        let mut h = Sha256::new();
        h.update(acc);
        h.update(&entry.r1);
        h.update(&entry.proof1);
        h.update(&entry.r2);
        h.update(&entry.proof2);
        acc = h.finalize().into();
    }
    acc
}

/// Re-export of the secp context type used internally — keeps the
/// boarding test harness terse.
pub fn new_secp() -> Secp256k1<secp256k1::All> {
    Secp256k1::new()
}

// ───────────────────────────────────────────────────────────────────────────
// ASP-side flow (#671)
// ───────────────────────────────────────────────────────────────────────────

use std::collections::HashMap;

use dark_von_musig2::setup::{RetainedScalars, Setup};

use crate::cohort::{BoardingState, CohortMember, HibernationHorizon};
use crate::slot_tree::SlotTree;

/// The artifact of a successful ASP-side boarding flow.
///
/// `RetainedScalars` carries the operator-only scalars `{r_{t,b}}` and
/// auto-zeroizes on drop; do not serialize or transport this struct
/// outside the ASP's process.
pub struct ActiveCohort {
    pub cohort: Cohort,
    pub retained: RetainedScalars,
    pub schedule: PublishedSchedule,
    pub setup_id: [u8; 32],
    pub slot_root: SlotRoot,
    /// Batch-tree root committing the cohort's renewal output structure
    /// (issue #672 / #680 follow-up for amount wiring). Recomputable
    /// from `cohort` via [`crate::batch_tree::compute_batch_tree_root`].
    pub batch_tree_root: [u8; 32],
    pub attest: SlotAttest,
    /// 32-byte raw txid of the on-chain publication, if step 4 of the
    /// flow ran (regtest only). `None` for off-chain-only flows used by
    /// unit tests and the K=100/N=12 happy path.
    pub publish_txid: Option<[u8; 32]>,
    /// User boarding artifacts keyed by `user_id`.
    pub artifacts: HashMap<[u8; 32], UserBoardingArtifact>,
}

/// ASP-side boarding (#671).
///
/// This is the off-chain orchestration entry point: it runs Setup,
/// builds the slot tree, signs `SlotAttest`, and drives every member
/// through `user_board`, producing an [`ActiveCohort`] in the
/// `Active` state. On-chain publication of `SlotAttest` (step 4 of
/// the issue text) is decoupled into [`asp_publish_attest`] so this
/// function stays buildable without the `regtest` feature; the test
/// harness at K=100/N=12 exercises the off-chain path.
///
/// The convenience signature accepts user keypairs alongside members
/// — phase 5 (CLI) will replace this with a network-driven collector
/// that streams `UserBoardingArtifact`s back from each user.
pub fn asp_board<R: Rng + ?Sized>(
    asp_kp: &Keypair,
    cohort_id: [u8; 32],
    members_and_keys: Vec<(CohortMember, Keypair)>,
    horizon: HibernationHorizon,
    setup_id: [u8; 32],
    publish_txid: Option<[u8; 32]>,
    rng: &mut R,
) -> Result<ActiveCohort, PsarError> {
    if members_and_keys.is_empty() {
        return Err(PsarError::EmptyCohort);
    }

    let secp = Secp256k1::new();
    let asp_xonly = asp_kp.x_only_public_key().0;
    let (members, user_keys): (Vec<_>, Vec<_>) = members_and_keys.into_iter().unzip();

    // ─── 1. Cohort + state machine ───────────────────────────────────
    let mut cohort = Cohort::new(cohort_id, members, horizon)?;
    let batch_tree_root = crate::batch_tree::compute_batch_tree_root(&cohort);

    // ─── 2. Setup phase: Λ + retained scalars ────────────────────────
    let asp_sk = SecretKey::from_keypair(asp_kp);
    let (schedule, retained) = Setup::run(&asp_sk, &setup_id, horizon.n)?;

    // ─── 3. Slot tree + SlotAttest signing ───────────────────────────
    let tree = SlotTree::from_members(&cohort.members);
    let slot_root = tree.root();
    let unsigned = SlotAttestUnsigned {
        slot_root: slot_root.0,
        cohort_id,
        setup_id,
        n: horizon.n,
        k: cohort.k(),
    };
    let attest = unsigned.sign(&secp, asp_kp);
    cohort.slot_root = Some(slot_root.0);
    cohort.transition(BoardingState::Committed)?;

    // ─── 4. (External) publish SlotAttest on regtest ─────────────────
    // Caller wires this via asp_publish_attest behind the `regtest`
    // feature. The optional `publish_txid` argument captures the
    // returned Txid.

    // ─── 5. Drive each user through user_board ───────────────────────
    let mut artifacts: HashMap<[u8; 32], UserBoardingArtifact> = HashMap::new();
    // Iterate by slot_index from the cohort's authoritative member
    // list so the per-user keypair lookup matches the slot it occupies.
    let user_kps_by_slot: HashMap<u32, &Keypair> = cohort
        .members
        .iter()
        .zip(user_keys.iter())
        .map(|(m, kp)| (m.slot_index, kp))
        .collect();
    for member in &cohort.members {
        let kp = user_kps_by_slot
            .get(&member.slot_index)
            .ok_or(PsarError::PubkeyMismatch {
                slot_index: member.slot_index,
            })?;
        let artifact = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &schedule,
            kp,
            member.slot_index,
            batch_tree_root,
            rng,
        )?;
        artifacts.insert(member.user_id, artifact);
    }
    cohort.transition(BoardingState::Active)?;

    Ok(ActiveCohort {
        cohort,
        retained,
        schedule,
        setup_id,
        slot_root,
        batch_tree_root,
        attest,
        publish_txid,
        artifacts,
    })
}

/// Publish an `ActiveCohort`'s [`SlotAttest`] on-chain via OP_RETURN
/// and stamp the resulting txid into `publish_txid`. Behind the
/// `regtest` feature.
#[cfg(feature = "regtest")]
pub fn asp_publish_attest(
    client: &bitcoincore_rpc::Client,
    active: &mut ActiveCohort,
) -> Result<bitcoin::Txid, crate::publish::PublishError> {
    use bitcoin::hashes::Hash;
    let txid = crate::publish::publish_slot_attest(client, &active.attest)?;
    active.publish_txid = Some(*txid.as_raw_hash().as_byte_array());
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{SlotAttest, SlotAttestUnsigned};
    use crate::cohort::{Cohort, CohortMember, HibernationHorizon};
    use crate::slot_tree::SlotRoot;
    use dark_von_musig2::setup::Setup;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    /// Find a SecretKey with even-parity x-only pubkey by counter-seeding.
    fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
        for offset in 0u32..1000 {
            let mut bytes = [seed; 32];
            // Avoid the all-equal trap by mixing in the offset.
            bytes[28..32].copy_from_slice(&offset.to_le_bytes());
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let kp = Keypair::from_secret_key(secp, &sk);
                if kp.x_only_public_key().1 == Parity::Even {
                    return kp;
                }
            }
        }
        panic!("no even-parity keypair found within counter range; should be ~50% probable");
    }

    fn cohort_with_keypairs(
        k: u32,
        horizon: HibernationHorizon,
    ) -> (Cohort, Vec<Keypair>, [u8; 32]) {
        let secp = Secp256k1::new();
        let mut keypairs = Vec::with_capacity(k as usize);
        let mut members = Vec::with_capacity(k as usize);
        for i in 0..k {
            let kp = even_parity_keypair(&secp, (i + 1) as u8);
            let xonly = kp.x_only_public_key().0.serialize();
            keypairs.push(kp);
            members.push(CohortMember {
                user_id: [i as u8 + 0x80; 32],
                pk_user: xonly,
                slot_index: i,
            });
        }
        let cohort_id = [0xab; 32];
        let cohort = Cohort::new(cohort_id, members, horizon).expect("cohort");
        (cohort, keypairs, cohort_id)
    }

    fn build_attest_and_schedule(
        cohort: &Cohort,
        asp_kp: &Keypair,
    ) -> (SlotAttest, PublishedSchedule, [u8; 32]) {
        let secp = Secp256k1::new();
        let asp_sk = SecretKey::from_keypair(asp_kp);
        let setup_id_bytes = [0xc4u8; 32];
        let (schedule, _retained) =
            Setup::run(&asp_sk, &setup_id_bytes, cohort.horizon.n).expect("setup");
        let slot_root = SlotRoot::compute(&cohort.members).0;
        let unsigned = SlotAttestUnsigned {
            slot_root,
            cohort_id: cohort.id,
            setup_id: setup_id_bytes,
            n: cohort.horizon.n,
            k: cohort.k(),
        };
        let attest = unsigned.sign(&secp, asp_kp);
        (attest, schedule, setup_id_bytes)
    }

    #[test]
    fn user_board_happy_path_k10_n4() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _cohort_id) = cohort_with_keypairs(10, horizon);
        let (attest, schedule, _setup_id) = build_attest_and_schedule(&cohort, &asp_kp);
        let batch_root = crate::batch_tree::compute_batch_tree_root(&cohort);

        let user_idx = 3u32;
        let user_kp = &keypairs[user_idx as usize];

        let mut rng = StdRng::seed_from_u64(0xface);
        let artifact = user_board(
            &cohort, &attest, &asp_xonly, &schedule, user_kp, user_idx, batch_root, &mut rng,
        )
        .expect("user_board");

        assert_eq!(artifact.slot_index, user_idx);
        assert_eq!(artifact.n, 4);
        assert_eq!(artifact.presigned.len(), 4);
        // Every PreSigned must carry well-formed bytes.
        for ps in &artifact.presigned {
            assert_eq!(ps.pub_nonce.to_bytes().len(), 66);
            assert_eq!(ps.partial_sig.to_bytes().len(), 32);
        }

        // The schedule witness is deterministic in Λ.
        let again = user_board(
            &cohort, &attest, &asp_xonly, &schedule, user_kp, user_idx, batch_root, &mut rng,
        )
        .expect("second run");
        assert_eq!(artifact.schedule_witness, again.schedule_witness);
    }

    #[test]
    fn user_board_aborts_on_mutated_lambda() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _) = cohort_with_keypairs(10, horizon);
        let (attest, mut schedule, _) = build_attest_and_schedule(&cohort, &asp_kp);

        // Mutate a single byte of the proof in epoch 2, slot 1.
        schedule.entries[1].proof1[0] ^= 0x01;

        let mut rng = StdRng::seed_from_u64(0xbeef);
        let err = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &schedule,
            &keypairs[3],
            3,
            crate::batch_tree::compute_batch_tree_root(&cohort),
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(err, PsarError::ScheduleInvalid { epoch: 2, slot: 1 }),
            "got {err:?}"
        );
    }

    #[test]
    fn user_board_rejects_mismatched_slot_index() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _) = cohort_with_keypairs(10, horizon);
        let (attest, schedule, _) = build_attest_and_schedule(&cohort, &asp_kp);

        let mut rng = StdRng::seed_from_u64(1);
        let err = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &schedule,
            &keypairs[3],
            5,
            crate::batch_tree::compute_batch_tree_root(&cohort),
            &mut rng,
        )
        .unwrap_err();
        assert!(
            matches!(err, PsarError::PubkeyMismatch { slot_index: 5 }),
            "got {err:?}"
        );
    }

    #[test]
    fn user_board_rejects_out_of_range_slot() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _) = cohort_with_keypairs(10, horizon);
        let (attest, schedule, _) = build_attest_and_schedule(&cohort, &asp_kp);

        let mut rng = StdRng::seed_from_u64(2);
        let err = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &schedule,
            &keypairs[3],
            99,
            crate::batch_tree::compute_batch_tree_root(&cohort),
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, PsarError::SlotIndexOutOfRange { .. }));
    }

    #[test]
    fn user_board_rejects_horizon_mismatch() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _) = cohort_with_keypairs(10, horizon);
        let (attest, _schedule, setup_id) = build_attest_and_schedule(&cohort, &asp_kp);
        // Build a schedule with a different horizon.
        let asp_sk = SecretKey::from_keypair(&asp_kp);
        let (other_schedule, _) = Setup::run(&asp_sk, &setup_id, 8).unwrap();

        let mut rng = StdRng::seed_from_u64(3);
        let err = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &other_schedule,
            &keypairs[3],
            3,
            crate::batch_tree::compute_batch_tree_root(&cohort),
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PsarError::HorizonDisagrees {
                schedule_n: 8,
                cohort_n: 4,
            }
        ));
    }

    #[test]
    fn user_board_rejects_tampered_attest_signature() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let horizon = HibernationHorizon::new(4, 12).unwrap();
        let (cohort, keypairs, _) = cohort_with_keypairs(10, horizon);
        let (mut attest, schedule, _) = build_attest_and_schedule(&cohort, &asp_kp);
        attest.sig[0] ^= 0x01;

        let mut rng = StdRng::seed_from_u64(4);
        let err = user_board(
            &cohort,
            &attest,
            &asp_xonly,
            &schedule,
            &keypairs[3],
            3,
            crate::batch_tree::compute_batch_tree_root(&cohort),
            &mut rng,
        )
        .unwrap_err();
        assert!(matches!(err, PsarError::AttestationVerify), "got {err:?}");
    }

    #[test]
    fn schedule_witness_changes_when_lambda_mutates() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let asp_sk = SecretKey::from_keypair(&asp_kp);
        let setup_id = [0xc4u8; 32];
        let (mut schedule, _) = Setup::run(&asp_sk, &setup_id, 4).unwrap();
        let w0 = compute_schedule_witness(&schedule);
        schedule.entries[0].r1[0] ^= 0x01;
        let w1 = compute_schedule_witness(&schedule);
        assert_ne!(w0, w1);
    }

    // ─── ASP-side flow tests (#671) ────────────────────────────────────

    fn cohort_with_kp_pairs(k: u32) -> (Vec<(CohortMember, Keypair)>, [u8; 32]) {
        let secp = Secp256k1::new();
        let mut out = Vec::with_capacity(k as usize);
        for i in 0..k {
            let kp = even_parity_keypair(&secp, (i + 1) as u8);
            let xonly = kp.x_only_public_key().0.serialize();
            out.push((
                CohortMember {
                    user_id: [(i & 0xff) as u8; 32],
                    pk_user: xonly,
                    slot_index: i,
                },
                kp,
            ));
        }
        // Spread user_ids beyond `K=255` so tests never duplicate them.
        for (idx, (m, _)) in out.iter_mut().enumerate() {
            m.user_id[0] = ((idx >> 8) & 0xff) as u8;
            m.user_id[1] = (idx & 0xff) as u8;
        }
        (out, [0xab; 32])
    }

    #[test]
    fn asp_board_happy_path_k4_n2() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let horizon = HibernationHorizon::new(2, 12).unwrap();
        let (members_kps, cohort_id) = cohort_with_kp_pairs(4);
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        let active = asp_board(
            &asp_kp,
            cohort_id,
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .expect("asp_board");

        assert_eq!(active.cohort.k(), 4);
        assert_eq!(active.cohort.state(), BoardingState::Active);
        assert_eq!(active.artifacts.len(), 4);
        assert_eq!(active.schedule.n, 2);
        assert!(active.publish_txid.is_none());
        // Schedule witness across all artifacts is identical (same Λ).
        let witnesses: std::collections::HashSet<[u8; 32]> = active
            .artifacts
            .values()
            .map(|a| a.schedule_witness)
            .collect();
        assert_eq!(witnesses.len(), 1, "all users should witness the same Λ");
    }

    #[test]
    fn asp_board_rejects_empty_member_set() {
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let horizon = HibernationHorizon::new(2, 12).unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let result = asp_board(
            &asp_kp,
            [0; 32],
            Vec::new(),
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        );
        match result {
            Err(PsarError::EmptyCohort) => {}
            Err(other) => panic!("expected EmptyCohort, got {other:?}"),
            Ok(_) => panic!("expected EmptyCohort error, got Ok"),
        }
    }

    #[test]
    fn asp_board_k100_n12_under_60_seconds() {
        // Issue #671 acceptance: K=100, N=12 ASP-side flow runs to
        // ActiveCohort under 60 s on dev hardware.
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0xaa);
        let horizon = HibernationHorizon::new(12, 12).unwrap();
        let (members_kps, cohort_id) = cohort_with_kp_pairs(100);
        let mut rng = StdRng::seed_from_u64(0xdada);

        let start = std::time::Instant::now();
        let active = asp_board(
            &asp_kp,
            cohort_id,
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .expect("asp_board K=100 N=12");
        let elapsed = start.elapsed();

        assert_eq!(active.cohort.k(), 100);
        assert_eq!(active.cohort.state(), BoardingState::Active);
        assert_eq!(active.artifacts.len(), 100);
        for art in active.artifacts.values() {
            assert_eq!(art.n, 12);
            assert_eq!(art.presigned.len(), 12);
        }
        assert!(
            elapsed.as_secs() < 60,
            "K=100/N=12 took {elapsed:?} (acceptance budget: 60 s)"
        );
    }

    #[test]
    fn asp_board_persists_into_in_memory_store() {
        use crate::store::{ActiveCohortStore, InMemoryActiveCohortStore};
        let secp = Secp256k1::new();
        let asp_kp = even_parity_keypair(&secp, 0x77);
        let horizon = HibernationHorizon::new(2, 12).unwrap();
        let (members_kps, cohort_id) = cohort_with_kp_pairs(3);
        let mut rng = StdRng::seed_from_u64(2);
        let active = asp_board(
            &asp_kp,
            cohort_id,
            members_kps,
            horizon,
            [0xc4; 32],
            Some([0x42; 32]),
            &mut rng,
        )
        .unwrap();

        let mut store = InMemoryActiveCohortStore::new();
        store.save(active).unwrap();
        let loaded = store.load(&cohort_id).expect("loaded");
        assert_eq!(loaded.cohort.k(), 3);
        assert_eq!(loaded.publish_txid, Some([0x42; 32]));
        assert_eq!(store.all().len(), 1);
    }
}
