//! ASP per-epoch processing (issue #673).
//!
//! Given an [`ActiveCohort`] and an epoch `t ∈ [1, n]`, [`process_epoch`]
//! produces the final BIP-340 Schnorr signature for every cohort
//! member by:
//!
//! 1. Re-deriving `m_t = derive_message_for_epoch(slot_root,
//!    batch_tree_root, t, n)` (same input the user fed at boarding
//!    time, #670).
//! 2. For each `(member, artifact)` pair: rebuild the 2-of-2
//!    `KeyAggCtx` over `[asp_pk_full, member_pk_full]` and call
//!    `dark_von_musig2::epoch::sign_epoch` with the operator's
//!    retained scalars.
//! 3. Validating the user's partial sig is part of `sign_epoch`
//!    (`PartialSigVerify`); a malformed user partial surfaces as
//!    [`PsarError::InvalidUserPartial`] and is collected into
//!    [`EpochArtifacts::failures`] so the ASP can skip-and-evict
//!    without aborting the rest of the cohort.
//!
//! After every member has been processed (success or failure), the
//! cohort state advances `Active → InProgress(t) → Active` (or
//! `→ Concluded` on `t == n`) via the
//! [`crate::lifecycle`] state machine.

use std::collections::HashMap;

use dark_von_musig2::epoch::sign_epoch;
use dark_von_musig2::sign::build_key_agg_ctx;
use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey};

use crate::boarding::ActiveCohort;
use crate::cohort::CohortState;
use crate::error::PsarError;
use crate::message::derive_message_for_epoch;

/// Per-epoch output handed back to the caller.
#[derive(Clone, Debug)]
pub struct EpochArtifacts {
    pub epoch: u32,
    pub n: u32,
    /// Aggregated 64-byte BIP-340 signatures keyed by `CohortMember::user_id`.
    pub signatures: HashMap<[u8; 32], [u8; 64]>,
    /// User ids whose partial signature failed verification this
    /// epoch. The ASP's eviction policy is out of scope for #673
    /// — for now the cohort retains them, the failure is recorded.
    pub failures: Vec<[u8; 32]>,
}

impl EpochArtifacts {
    /// `true` iff every cohort member produced a valid sig.
    pub fn fully_complete(&self, expected_users: usize) -> bool {
        self.signatures.len() == expected_users && self.failures.is_empty()
    }
}

/// Run epoch `t` of the renewal protocol against `active_cohort`.
///
/// Mutates `active_cohort.cohort.state` through `Active → InProgress(t)
/// → Active` (or `→ Concluded` when `t == n`); returns `EpochArtifacts`
/// containing the per-user 64-byte BIP-340 signatures.
pub fn process_epoch(
    active_cohort: &mut ActiveCohort,
    asp_kp: &Keypair,
    t: u32,
) -> Result<EpochArtifacts, PsarError> {
    let n = active_cohort.cohort.horizon.n;
    if t == 0 || t > n {
        return Err(PsarError::EpochOutOfRange { epoch: t, n });
    }

    // ─── Lifecycle: Active → InProgress(t) ───────────────────────────
    active_cohort
        .cohort
        .transition(CohortState::InProgress(t))?;

    let m_t = derive_message_for_epoch(
        active_cohort.slot_root.as_bytes(),
        &active_cohort.batch_tree_root,
        t,
        n,
    );
    let asp_sk = SecretKey::from_keypair(asp_kp);
    let asp_xonly = asp_kp.x_only_public_key().0;
    let asp_pk_full = lift_xonly_to_even(&asp_xonly);

    let mut signatures: HashMap<[u8; 32], [u8; 64]> = HashMap::new();
    let mut failures: Vec<[u8; 32]> = Vec::new();

    for member in &active_cohort.cohort.members {
        let artifact =
            active_cohort
                .artifacts
                .get(&member.user_id)
                .ok_or(PsarError::PubkeyMismatch {
                    slot_index: member.slot_index,
                })?;
        let presigned = artifact
            .presigned
            .get((t - 1) as usize)
            .ok_or(PsarError::EpochOutOfRange { epoch: t, n })?;

        let user_pk_xonly =
            XOnlyPublicKey::from_slice(&member.pk_user).map_err(|_| PsarError::PubkeyMismatch {
                slot_index: member.slot_index,
            })?;
        let user_pk_full = lift_xonly_to_even(&user_pk_xonly);
        let ctx = build_key_agg_ctx(&[asp_pk_full, user_pk_full])
            .map_err(|e| PsarError::VonMusig2(dark_von_musig2::VonMusig2Error::Bip327(e)))?;

        match sign_epoch(
            &active_cohort.retained,
            &asp_sk,
            t,
            &ctx,
            &user_pk_full,
            presigned,
            &m_t,
        ) {
            Ok(sig) => {
                signatures.insert(member.user_id, sig);
            }
            Err(dark_von_musig2::VonMusig2Error::InvalidParticipantPartialSig) => {
                failures.push(member.user_id);
            }
            Err(other) => return Err(PsarError::VonMusig2(other)),
        }
    }

    // ─── Lifecycle: InProgress(t) → Active (or → Concluded if t == n) ──
    active_cohort.cohort.transition(CohortState::Active)?;
    if t == n {
        active_cohort.cohort.transition(CohortState::Concluded)?;
    }

    Ok(EpochArtifacts {
        epoch: t,
        n,
        signatures,
        failures,
    })
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
    use crate::boarding::asp_board;
    use crate::cohort::{CohortMember, HibernationHorizon};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::{schnorr::Signature, Keypair, Message, Parity, Secp256k1, SecretKey};

    fn even_parity_keypair(secp: &Secp256k1<secp256k1::All>, seed: u8) -> Keypair {
        for offset in 0u32..1000 {
            let mut bytes = [seed; 32];
            bytes[28..32].copy_from_slice(&offset.to_le_bytes());
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let kp = Keypair::from_secret_key(secp, &sk);
                if kp.x_only_public_key().1 == Parity::Even {
                    return kp;
                }
            }
        }
        panic!("no even-parity keypair");
    }

    fn build_cohort(
        secp: &Secp256k1<secp256k1::All>,
        k: u32,
        n: u32,
    ) -> (Keypair, ActiveCohort, Vec<Keypair>) {
        let asp_kp = even_parity_keypair(secp, 0xa0);
        let horizon = HibernationHorizon::new(n, n.max(12)).unwrap();
        let mut keypairs = Vec::with_capacity(k as usize);
        let mut members_kps = Vec::with_capacity(k as usize);
        for i in 0..k {
            let kp = even_parity_keypair(secp, (i + 1) as u8);
            let xonly = kp.x_only_public_key().0.serialize();
            let mut user_id = [0u8; 32];
            user_id[0] = ((i >> 8) & 0xff) as u8;
            user_id[1] = (i & 0xff) as u8;
            keypairs.push(kp);
            members_kps.push((
                CohortMember {
                    user_id,
                    pk_user: xonly,
                    slot_index: i,
                },
                kp,
            ));
        }
        let mut rng = StdRng::seed_from_u64(0xdada);
        let active = asp_board(
            &asp_kp,
            [0xab; 32],
            members_kps,
            horizon,
            [0xc4; 32],
            None,
            &mut rng,
        )
        .expect("asp_board");
        (asp_kp, active, keypairs)
    }

    /// Verify a per-user BIP-340 sig against the 2-of-2 (asp + user)
    /// aggregate pubkey under `secp256k1::Secp256k1::verify_schnorr`.
    fn verify_user_sig(
        secp: &Secp256k1<secp256k1::All>,
        asp_xonly: &XOnlyPublicKey,
        user_xonly_bytes: &[u8; 32],
        m_t: &[u8; 32],
        sig_bytes: &[u8; 64],
    ) {
        let asp_full = lift_xonly_to_even(asp_xonly);
        let user_full = {
            let user_xonly = XOnlyPublicKey::from_slice(user_xonly_bytes).unwrap();
            lift_xonly_to_even(&user_xonly)
        };
        let ctx = build_key_agg_ctx(&[asp_full, user_full]).unwrap();
        let agg_xonly_bytes = ctx.x_only_pubkey();
        let agg_xonly = XOnlyPublicKey::from_slice(&agg_xonly_bytes).unwrap();
        let sig = Signature::from_slice(sig_bytes).unwrap();
        let msg = Message::from_digest(*m_t);
        secp.verify_schnorr(&sig, &msg, &agg_xonly)
            .expect("BIP-340 verify");
    }

    #[test]
    fn process_epoch_smoke_k4_n2() {
        let secp = Secp256k1::new();
        let (asp_kp, mut active, _keys) = build_cohort(&secp, 4, 2);
        let asp_xonly = asp_kp.x_only_public_key().0;

        let n = active.cohort.horizon.n;
        for t in 1..=n {
            let arts = process_epoch(&mut active, &asp_kp, t).expect("process_epoch");
            assert_eq!(arts.epoch, t);
            assert_eq!(arts.n, n);
            assert!(arts.fully_complete(active.cohort.k() as usize));

            // Verify each per-user sig under the 2-of-2 aggregate key.
            let m_t = derive_message_for_epoch(
                active.slot_root.as_bytes(),
                &active.batch_tree_root,
                t,
                n,
            );
            for member in &active.cohort.members {
                let sig = arts.signatures.get(&member.user_id).expect("sig present");
                verify_user_sig(&secp, &asp_xonly, &member.pk_user, &m_t, sig);
            }
        }
        assert_eq!(active.cohort.state(), CohortState::Concluded);
    }

    #[test]
    fn process_epoch_rejects_out_of_range() {
        let secp = Secp256k1::new();
        let (asp_kp, mut active, _) = build_cohort(&secp, 2, 2);
        // t = 0 is invalid.
        let err = process_epoch(&mut active, &asp_kp, 0).unwrap_err();
        assert!(matches!(err, PsarError::EpochOutOfRange { .. }));
        // t > n is invalid.
        let err = process_epoch(&mut active, &asp_kp, 99).unwrap_err();
        assert!(matches!(err, PsarError::EpochOutOfRange { .. }));
    }

    #[test]
    fn process_epoch_advances_lifecycle() {
        let secp = Secp256k1::new();
        let (asp_kp, mut active, _) = build_cohort(&secp, 2, 2);
        assert_eq!(active.cohort.state(), CohortState::Active);
        process_epoch(&mut active, &asp_kp, 1).unwrap();
        // After epoch 1 (t < n), state returned to Active.
        assert_eq!(active.cohort.state(), CohortState::Active);
        process_epoch(&mut active, &asp_kp, 2).unwrap();
        // After epoch n, Concluded.
        assert_eq!(active.cohort.state(), CohortState::Concluded);
    }

    /// Acceptance gate from issue #673: K=100, N=12 — every epoch
    /// produces 100 valid Schnorr signatures.
    #[test]
    fn process_epoch_k100_n12_all_valid() {
        let secp = Secp256k1::new();
        let (asp_kp, mut active, _) = build_cohort(&secp, 100, 12);
        let asp_xonly = asp_kp.x_only_public_key().0;
        let n = active.cohort.horizon.n;

        let start = std::time::Instant::now();
        for t in 1..=n {
            let arts = process_epoch(&mut active, &asp_kp, t).expect("process_epoch");
            assert!(arts.fully_complete(100));
            let m_t = derive_message_for_epoch(
                active.slot_root.as_bytes(),
                &active.batch_tree_root,
                t,
                n,
            );
            for member in &active.cohort.members {
                let sig = arts.signatures.get(&member.user_id).expect("sig present");
                verify_user_sig(&secp, &asp_xonly, &member.pk_user, &m_t, sig);
            }
        }
        let elapsed = start.elapsed();
        assert_eq!(active.cohort.state(), CohortState::Concluded);
        // Sanity budget — well under what ASP needs at this scale.
        assert!(
            elapsed.as_secs() < 60,
            "K=100/N=12 epoch processing took {elapsed:?}"
        );
    }

    #[test]
    fn process_epoch_skips_evicted_user() {
        // Tamper one user's partial sig and confirm:
        //  - The cohort still produces sigs for everyone else.
        //  - The tampered user lands in `failures`.
        let secp = Secp256k1::new();
        let (asp_kp, mut active, _) = build_cohort(&secp, 4, 2);

        // Pick the first user to corrupt.
        let target_user_id = active.cohort.members[0].user_id;
        let target_artifact = active.artifacts.get_mut(&target_user_id).unwrap();
        let mut tampered = target_artifact.presigned[0].partial_sig.to_bytes();
        tampered[0] ^= 0x01;
        target_artifact.presigned[0].partial_sig =
            dark_von_musig2::sign::PartialSignature::from_slice(&tampered).unwrap();

        let arts = process_epoch(&mut active, &asp_kp, 1).unwrap();
        assert_eq!(arts.signatures.len(), 3);
        assert_eq!(arts.failures, vec![target_user_id]);
        assert!(!arts.fully_complete(4));
    }
}
