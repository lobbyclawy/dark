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
//!    [`crate::bip327::sign::partial_sign_with_scalars`] using `(r_{t,1}, r_{t,2})`.
//! 4. Aggregate operator + participant partial sigs into a 64-byte BIP-340
//!    signature `(R_x, s)`.
//!
//! The resulting signature is wire-compatible with `musig2::verify_single`
//! and `bitcoin::secp256k1::Secp256k1::verify_schnorr` — exercised by
//! `tests/end_to_end_horizon.rs` (#665) and the integration test below.

use secp256k1::{PublicKey, SecretKey};

use crate::bip327::key_agg::KeyAggCtx;
use crate::bip327::sign::{aggregate_and_finalize, partial_sign_with_scalars};
use crate::error::VonMusig2Error;
use crate::nonces::{AggNonce, PubNonce};
use crate::presign::PreSigned;
use crate::setup::RetainedScalars;
use crate::sign::PartialSignature;

/// Operator's per-epoch signing path.
pub fn sign_epoch(
    retained: &RetainedScalars,
    operator_sk: &SecretKey,
    t: u32,
    ctx: &KeyAggCtx,
    participant: &PreSigned,
    msg: &[u8; 32],
) -> Result<[u8; 64], VonMusig2Error> {
    let r_op1 = retained
        .r(t, 1)
        .ok_or(VonMusig2Error::MalformedPublishedSchedule(
            "retained scalar at (t, b=1) missing",
        ))?;
    let r_op2 = retained
        .r(t, 2)
        .ok_or(VonMusig2Error::MalformedPublishedSchedule(
            "retained scalar at (t, b=2) missing",
        ))?;

    let secp = secp256k1::Secp256k1::new();
    let r_op_p1 = PublicKey::from_secret_key(&secp, r_op1);
    let r_op_p2 = PublicKey::from_secret_key(&secp, r_op2);
    let op_pubnonce = PubNonce {
        r1: r_op_p1,
        r2: r_op_p2,
    };

    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant.pub_nonce.clone()])?;

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
/// Useful when the operator's role is to contribute to a multi-party
/// aggregation done elsewhere.
pub fn operator_partial(
    retained: &RetainedScalars,
    operator_sk: &SecretKey,
    t: u32,
    ctx: &KeyAggCtx,
    participant_pub_nonce: &PubNonce,
    msg: &[u8; 32],
) -> Result<(AggNonce, PartialSignature), VonMusig2Error> {
    let r_op1 = retained
        .r(t, 1)
        .ok_or(VonMusig2Error::MalformedPublishedSchedule(
            "retained scalar at (t, b=1) missing",
        ))?;
    let r_op2 = retained
        .r(t, 2)
        .ok_or(VonMusig2Error::MalformedPublishedSchedule(
            "retained scalar at (t, b=2) missing",
        ))?;

    let secp = secp256k1::Secp256k1::new();
    let r_op_p1 = PublicKey::from_secret_key(&secp, r_op1);
    let r_op_p2 = PublicKey::from_secret_key(&secp, r_op2);
    let op_pubnonce = PubNonce {
        r1: r_op_p1,
        r2: r_op_p2,
    };

    let agg_nonce = AggNonce::sum(&[op_pubnonce, participant_pub_nonce.clone()])?;

    let s_op = partial_sign_with_scalars(ctx, operator_sk, r_op1, r_op2, &agg_nonce, msg)?;
    Ok((agg_nonce, PartialSignature(s_op)))
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
            let sig = sign_epoch(&retained, &op, t, &ctx, presigned_t, &msg).expect("sign_epoch");
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

        // Construct a dummy participant PreSigned (won't be reached since t is invalid).
        let dummy_r =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11u8; 32]).unwrap());
        let dummy_presigned = PreSigned {
            pub_nonce: PubNonce {
                r1: dummy_r,
                r2: dummy_r,
            },
            partial_sig: PartialSignature([0u8; 32]),
        };

        let result = sign_epoch(&retained, &op, 5, &ctx, &dummy_presigned, &[0u8; 32]);
        assert!(matches!(
            result,
            Err(VonMusig2Error::MalformedPublishedSchedule(_))
        ));
    }
}
