//! Per-epoch operator signing for VON-MuSig2.
//!
//! `sign_epoch(retained, operator_sk, t, ctx, participant, msg)` runs the
//! operator side of the protocol for one epoch:
//!
//! 1. Read operator's `(r_{t,1}, r_{t,2})` from [`RetainedScalars`].
//! 2. Recompute `R_{op} = (r_{t,1}·G, r_{t,2}·G)` and combine with the
//!    participant's pre-committed `PubNonce` from [`PreSigned`] to recover
//!    the same `agg_nonce` the participant signed against.
//! 3. Compute the operator's partial signature via
//!    `crate::bip327::sign::partial_sign_with_scalars` using `(r_{t,1}, r_{t,2})`.
//! 4. Aggregate operator + participant partial sigs into a 64-byte BIP-340
//!    signature `(R_x, s)`.
//!
//! The resulting signature is wire-compatible with `musig2::verify_single`
//! and `bitcoin::secp256k1::Secp256k1::verify_schnorr` — exercised by
//! `tests/end_to_end_horizon.rs` (#665) and the integration test below.

use secp256k1::{PublicKey, SecretKey};

use crate::bip327::key_agg::KeyAggCtx;
use crate::bip327::sign::{aggregate_and_finalize, partial_sig_verify, partial_sign_with_scalars};
use crate::error::VonMusig2Error;
use crate::nonces::{AggNonce, PubNonce};
use crate::presign::PreSigned;
use crate::setup::RetainedScalars;
use crate::sign::PartialSignature;

/// Operator's per-epoch signing path.
///
/// Validates `participant_pk` is in `ctx.pubkeys` and runs BIP-327
/// `PartialSigVerify` against `participant.partial_sig` **before** the operator
/// computes its own VON-bound partial signature against this `agg_nonce` —
/// without that check a malicious participant can either burn the operator's
/// pre-committed nonce slot or leak `sk_op` via two-sigs-same-nonce on retry.
pub fn sign_epoch(
    retained: &RetainedScalars,
    operator_sk: &SecretKey,
    t: u32,
    ctx: &KeyAggCtx,
    participant_pk: &PublicKey,
    participant: &PreSigned,
    msg: &[u8; 32],
) -> Result<[u8; 64], VonMusig2Error> {
    membership_check(operator_sk, participant_pk, ctx)?;

    let max = retained.n();
    let r_op1 = retained
        .r(t, 1)
        .ok_or(VonMusig2Error::EpochOutOfRange { t, max })?;
    let r_op2 = retained
        .r(t, 2)
        .ok_or(VonMusig2Error::EpochOutOfRange { t, max })?;

    let secp = secp256k1::Secp256k1::new();
    let r_op_p1 = PublicKey::from_secret_key(&secp, r_op1);
    let r_op_p2 = PublicKey::from_secret_key(&secp, r_op2);
    let op_pubnonce = PubNonce {
        r1: r_op_p1,
        r2: r_op_p2,
    };

    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant.pub_nonce.clone()])?;

    // Validate the participant's partial sig against the recovered agg_nonce
    // BEFORE we commit our VON-bound (r1, r2) to the operator's partial.
    partial_sig_verify(
        ctx,
        &agg_nonce,
        msg,
        participant_pk,
        &participant.pub_nonce,
        &participant.partial_sig.to_bytes(),
    )
    .map_err(|_| VonMusig2Error::InvalidParticipantPartialSig)?;

    let s_op = partial_sign_with_scalars(ctx, operator_sk, r_op1, r_op2, &agg_nonce, msg)?;

    let sig = aggregate_and_finalize(
        &agg_nonce,
        ctx,
        msg,
        &[s_op, participant.partial_sig.to_bytes()],
    )?;
    Ok(sig)
}

/// Convenience: operator partial signature alone, without aggregation.
///
/// Same membership and partial-sig-verify checks as [`sign_epoch`].
pub fn operator_partial(
    retained: &RetainedScalars,
    operator_sk: &SecretKey,
    t: u32,
    ctx: &KeyAggCtx,
    participant_pk: &PublicKey,
    participant: &PreSigned,
    msg: &[u8; 32],
) -> Result<(AggNonce, PartialSignature), VonMusig2Error> {
    membership_check(operator_sk, participant_pk, ctx)?;

    let max = retained.n();
    let r_op1 = retained
        .r(t, 1)
        .ok_or(VonMusig2Error::EpochOutOfRange { t, max })?;
    let r_op2 = retained
        .r(t, 2)
        .ok_or(VonMusig2Error::EpochOutOfRange { t, max })?;

    let secp = secp256k1::Secp256k1::new();
    let r_op_p1 = PublicKey::from_secret_key(&secp, r_op1);
    let r_op_p2 = PublicKey::from_secret_key(&secp, r_op2);
    let op_pubnonce = PubNonce {
        r1: r_op_p1,
        r2: r_op_p2,
    };

    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant.pub_nonce.clone()])?;

    partial_sig_verify(
        ctx,
        &agg_nonce,
        msg,
        participant_pk,
        &participant.pub_nonce,
        &participant.partial_sig.to_bytes(),
    )
    .map_err(|_| VonMusig2Error::InvalidParticipantPartialSig)?;

    let s_op = partial_sign_with_scalars(ctx, operator_sk, r_op1, r_op2, &agg_nonce, msg)?;
    Ok((agg_nonce, PartialSignature(s_op)))
}

fn membership_check(
    operator_sk: &SecretKey,
    participant_pk: &PublicKey,
    ctx: &KeyAggCtx,
) -> Result<(), VonMusig2Error> {
    let secp = secp256k1::Secp256k1::new();
    let op_pk = PublicKey::from_secret_key(&secp, operator_sk);
    if !ctx.pubkeys.contains(&op_pk) {
        return Err(VonMusig2Error::OperatorNotInKeyAgg);
    }
    if !ctx.pubkeys.contains(participant_pk) {
        return Err(VonMusig2Error::OperatorNotInKeyAgg);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presign::presign_horizon;
    use crate::setup::Setup;
    use crate::sign::build_key_agg_ctx;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use secp256k1::Secp256k1;

    fn op_sk() -> SecretKey {
        SecretKey::from_slice(&[0xa1u8; 32]).unwrap()
    }

    fn part_sk() -> SecretKey {
        SecretKey::from_slice(&[0xb2u8; 32]).unwrap()
    }

    fn pk_31_from_29(pk: &PublicKey) -> musig2::secp256k1::PublicKey {
        musig2::secp256k1::PublicKey::from_slice(&pk.serialize()).unwrap()
    }

    /// End-to-end N=12 horizon — the headline acceptance test.
    #[test]
    fn end_to_end_horizon_n12_verifies() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();

        let setup_id = [0xc4u8; 32];
        let n = 12u32;
        let (published, retained) = Setup::run(&op, &setup_id, n).unwrap();

        // Per-epoch messages.
        let messages: Vec<[u8; 32]> = (0..n)
            .map(|i| {
                let mut m = [0u8; 32];
                m[28..32].copy_from_slice(&i.to_be_bytes());
                m
            })
            .collect();

        // Participant pre-signs the whole horizon.
        let mut rng = StdRng::seed_from_u64(0xface_bee5);
        let presigned =
            presign_horizon(&part, &op_pk, &ctx, &published, &messages, &mut rng).expect("presign");
        assert_eq!(presigned.len(), n as usize);

        // Operator signs every epoch; each sig must verify under musig2's BIP-340 verifier.
        let agg_pk_31 = {
            let pks = vec![pk_31_from_29(&op_pk), pk_31_from_29(&part_pk)];
            musig2::KeyAggContext::new(pks)
                .unwrap()
                .aggregated_pubkey::<musig2::secp256k1::PublicKey>()
        };

        for (idx, presigned_t) in presigned.iter().enumerate() {
            let t = (idx + 1) as u32;
            let msg = messages[idx];
            let sig = sign_epoch(&retained, &op, t, &ctx, &part_pk, presigned_t, &msg)
                .expect("sign_epoch");
            musig2::verify_single(agg_pk_31, sig, msg).unwrap_or_else(|e| {
                panic!("epoch {t}: BIP-340 verify failed: {e}");
            });
        }
    }

    #[test]
    fn sign_epoch_rejects_out_of_range_t() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (_published, retained) = Setup::run(&op, &[0u8; 32], 4).unwrap();

        let dummy_r =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11u8; 32]).unwrap());
        let dummy_presigned = PreSigned {
            pub_nonce: PubNonce {
                r1: dummy_r,
                r2: dummy_r,
            },
            partial_sig: PartialSignature([0u8; 32]),
        };

        let result = sign_epoch(
            &retained,
            &op,
            5,
            &ctx,
            &part_pk,
            &dummy_presigned,
            &[0u8; 32],
        );
        assert!(matches!(
            result,
            Err(VonMusig2Error::EpochOutOfRange { t: 5, max: 4 })
        ));
    }

    #[test]
    fn sign_epoch_rejects_operator_not_in_keyagg() {
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let bystander = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let bystander_pk = PublicKey::from_secret_key(&secp, &bystander);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        // ctx excludes the bystander; bystander tries to sign as operator.
        let ctx = build_key_agg_ctx(&[PublicKey::from_secret_key(&secp, &op), part_pk]).unwrap();
        let (_published, retained) = Setup::run(&bystander, &[0u8; 32], 1).unwrap();

        let dummy_r =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11u8; 32]).unwrap());
        let dummy_presigned = PreSigned {
            pub_nonce: PubNonce {
                r1: dummy_r,
                r2: dummy_r,
            },
            partial_sig: PartialSignature([0u8; 32]),
        };

        let _ = bystander_pk;
        let result = sign_epoch(
            &retained,
            &bystander,
            1,
            &ctx,
            &part_pk,
            &dummy_presigned,
            &[0u8; 32],
        );
        assert!(matches!(result, Err(VonMusig2Error::OperatorNotInKeyAgg)));
    }

    #[test]
    fn sign_epoch_rejects_bogus_participant_partial_sig() {
        // Bug fix #002: malicious participant submits valid pub_nonce + bogus
        // partial_sig. sign_epoch must reject BEFORE computing operator's
        // partial — otherwise operator's nonce slot would be burned (or sk_op
        // leaked via two-sigs-same-nonce on retry).
        let secp = Secp256k1::new();
        let op = op_sk();
        let part = part_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk = PublicKey::from_secret_key(&secp, &part);
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (published, retained) = Setup::run(&op, &[0xaau8; 32], 1).unwrap();
        let messages = [[0xbbu8; 32]];

        let mut rng = StdRng::seed_from_u64(7);
        let mut presigned =
            presign_horizon(&part, &op_pk, &ctx, &published, &messages, &mut rng).expect("presign");

        // Tamper with the participant's partial sig (flip a bit).
        let mut bogus = presigned[0].partial_sig.to_bytes();
        bogus[0] ^= 0x01;
        presigned[0].partial_sig = PartialSignature(bogus);

        let result = sign_epoch(
            &retained,
            &op,
            1,
            &ctx,
            &part_pk,
            &presigned[0],
            &messages[0],
        );
        assert!(matches!(
            result,
            Err(VonMusig2Error::InvalidParticipantPartialSig)
        ));
    }

    #[test]
    fn sign_epoch_survives_negated_participant_nonce() {
        // Bug fix #001: malicious participant negates op's R contributions to
        // force sum-to-infinity; AggNonce::sum's G fallback closes that DoS.
        // Combined with #002's PartialSigVerify, the bogus partial_sig is
        // detected and the operator returns InvalidParticipantPartialSig
        // instead of crashing on infinity.
        let secp = Secp256k1::new();
        let op = op_sk();
        let op_pk = PublicKey::from_secret_key(&secp, &op);
        let part_pk =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0xb2u8; 32]).unwrap());
        let ctx = build_key_agg_ctx(&[op_pk, part_pk]).unwrap();
        let (published, retained) = Setup::run(&op, &[0xccu8; 32], 1).unwrap();

        // Read the operator's published R for slot (1, 1) and (1, 2).
        let pub_dv = published.to_dark_von().unwrap();
        let r_op_1 = pub_dv.entry(1, 1).unwrap().r_point;
        let r_op_2 = pub_dv.entry(1, 2).unwrap().r_point;

        // Adversarial pub_nonce: negate both.
        let adversarial_pubnonce = PubNonce {
            r1: r_op_1.negate(&secp),
            r2: r_op_2.negate(&secp),
        };
        let presigned_evil = PreSigned {
            pub_nonce: adversarial_pubnonce,
            partial_sig: PartialSignature([0xdeu8; 32]), // arbitrary
        };

        // Should NOT panic / crash on AggregateInfinity; should reject at
        // PartialSigVerify since adversary doesn't know discrete log.
        let result = sign_epoch(
            &retained,
            &op,
            1,
            &ctx,
            &part_pk,
            &presigned_evil,
            &[0u8; 32],
        );
        assert!(matches!(
            result,
            Err(VonMusig2Error::InvalidParticipantPartialSig)
        ));
    }
}
