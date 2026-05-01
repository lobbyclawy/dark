//! BIP-327 §"Signing": nonce coefficient, BIP-340 challenge, partial signing.

use secp256k1::{PublicKey, Scalar, SecretKey};
use zeroize::Zeroizing;

use crate::error::Bip327Error;
use crate::nonces::AggNonce;

use super::internal::{generator, has_even_y, neg_mod_n, reduce_mod_n, scalar_of, secp};
use super::key_agg::{key_agg_coeff, KeyAggCtx};
use super::tagged::{tagged, BIP0340_CHALLENGE_TAG, MUSIG_NONCECOEF_TAG};

/// Session values derived from the agg-nonce, agg key, and message.
pub struct SessionValues {
    /// `b = H_noncecoef(aggnonce || Q_x || msg) mod n`.
    pub b: Scalar,
    /// Final aggregated nonce point `R = R_agg,1 + b · R_agg,2`.
    pub r: PublicKey,
    /// BIP-340 challenge `e = H_BIP340_challenge(R_x || Q_x || msg) mod n`.
    pub e: Scalar,
}

/// Compute the per-session values `(b, R, e)` per BIP-327.
pub fn session_values(
    agg_nonce: &AggNonce,
    ctx: &KeyAggCtx,
    msg: &[u8; 32],
) -> Result<SessionValues, Bip327Error> {
    let agg_bytes = agg_nonce.to_bytes();
    let q_x = ctx.x_only_pubkey();

    let b_hash = tagged(
        &MUSIG_NONCECOEF_TAG,
        &[agg_bytes.as_slice(), q_x.as_slice(), msg.as_slice()],
    );
    let b_bytes = reduce_mod_n(&b_hash);
    let b = Scalar::from_be_bytes(b_bytes).map_err(|_| Bip327Error::ScalarZero)?;

    // R = R_agg,1 + b · R_agg,2 with G fallback per BIP-327 §GetSessionValues.
    let r2_b = agg_nonce
        .r2
        .mul_tweak(secp(), &b)
        .map_err(|_| Bip327Error::ScalarZero)?;
    let r = match agg_nonce.r1.combine(&r2_b) {
        Ok(p) => p,
        Err(_) => *generator(),
    };

    let mut r_x = [0u8; 32];
    r_x.copy_from_slice(&r.serialize()[1..]);
    let e_hash = tagged(
        &BIP0340_CHALLENGE_TAG,
        &[r_x.as_slice(), q_x.as_slice(), msg.as_slice()],
    );
    let e_bytes = reduce_mod_n(&e_hash);
    let e = Scalar::from_be_bytes(e_bytes).map_err(|_| Bip327Error::ScalarZero)?;

    Ok(SessionValues { b, r, e })
}

/// `sign_partial_with_scalars` per BIP-327 §"Signing", but the signer's
/// `(k₁, k₂)` are passed in directly (rather than parsed from a `secnonce`
/// blob produced by `NonceGen`). This is the entry point VON callers use.
///
/// Returns the 32-byte partial-signature scalar `s_i`.
pub fn partial_sign_with_scalars(
    ctx: &KeyAggCtx,
    operator_sk: &SecretKey,
    k1: &SecretKey,
    k2: &SecretKey,
    agg_nonce: &AggNonce,
    msg: &[u8; 32],
) -> Result<[u8; 32], Bip327Error> {
    let sv = session_values(agg_nonce, ctx, msg)?;

    // Apply R-parity flip: if R has odd y, negate (k₁, k₂).
    let r_even = has_even_y(&sv.r);
    let k1_b = if r_even {
        k1.secret_bytes()
    } else {
        neg_mod_n(&k1.secret_bytes())
    };
    let k2_b = if r_even {
        k2.secret_bytes()
    } else {
        neg_mod_n(&k2.secret_bytes())
    };
    let k1_z = Zeroizing::new(k1_b);
    let k2_z = Zeroizing::new(k2_b);

    // Apply Q-parity flip: if Q has odd y, negate sk.
    let q_even = ctx.q_has_even_y();
    let sk_eff_bytes = if q_even {
        operator_sk.secret_bytes()
    } else {
        neg_mod_n(&operator_sk.secret_bytes())
    };
    let sk_eff_z = Zeroizing::new(sk_eff_bytes);
    // sk_eff is non-zero iff operator_sk is non-zero (which it is — SecretKey type).
    let sk_eff = SecretKey::from_slice(&*sk_eff_z).map_err(|_| Bip327Error::ScalarZero)?;

    let operator_pk = PublicKey::from_secret_key(secp(), operator_sk);
    let a = key_agg_coeff(ctx, &operator_pk)?;

    // s = k1 + b · k2 + e · a · sk_eff (mod n)
    // Compute the right-hand side step by step using SecretKey scalar arithmetic.
    let e_a = e_times_a(&sv.e, &a)?;
    let e_a_sk = sk_eff
        .mul_tweak(&e_a)
        .map_err(|_| Bip327Error::ScalarZero)?;

    let b_k2 = mul_scalar(&k2_z, &sv.b)?;

    // s = k1 + b·k2 + e·a·sk_eff. Intermediate scalars wrap in Zeroizing
    // so they wipe on drop; the final partial-sig scalar is public output.
    let mut acc: Zeroizing<[u8; 32]> = k1_z.clone();
    acc = add_mod_n(&acc, &b_k2)?;
    let e_a_sk_bytes = Zeroizing::new(e_a_sk.secret_bytes());
    acc = add_mod_n(&acc, &e_a_sk_bytes)?;

    Ok(*acc)
}

fn e_times_a(e: &Scalar, a: &Scalar) -> Result<Scalar, Bip327Error> {
    // Use SecretKey::mul_tweak (rejects zero; e and a are non-zero except at
    // negligible probability under random inputs).
    let e_sk = SecretKey::from_slice(&e.to_be_bytes()).map_err(|_| Bip327Error::ScalarZero)?;
    let prod = e_sk.mul_tweak(a).map_err(|_| Bip327Error::ScalarZero)?;
    Ok(scalar_of(&prod))
}

fn mul_scalar(
    scalar_bytes: &[u8; 32],
    factor: &Scalar,
) -> Result<Zeroizing<[u8; 32]>, Bip327Error> {
    if scalar_bytes == &[0u8; 32] {
        return Ok(Zeroizing::new([0u8; 32]));
    }
    let sk = SecretKey::from_slice(scalar_bytes).map_err(|_| Bip327Error::ScalarZero)?;
    let prod = sk.mul_tweak(factor).map_err(|_| Bip327Error::ScalarZero)?;
    Ok(Zeroizing::new(prod.secret_bytes()))
}

fn add_mod_n(a_bytes: &[u8; 32], b_bytes: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Bip327Error> {
    if a_bytes == &[0u8; 32] {
        return Ok(Zeroizing::new(*b_bytes));
    }
    if b_bytes == &[0u8; 32] {
        return Ok(Zeroizing::new(*a_bytes));
    }
    let a_sk = SecretKey::from_slice(a_bytes).map_err(|_| Bip327Error::ScalarZero)?;
    let b_scalar = Scalar::from_be_bytes(*b_bytes).map_err(|_| Bip327Error::ScalarZero)?;
    match a_sk.add_tweak(&b_scalar) {
        Ok(sum) => Ok(Zeroizing::new(sum.secret_bytes())),
        Err(_) => Ok(Zeroizing::new([0u8; 32])), // exact additive cancellation; legal but rare
    }
}

/// Aggregate partial-sig scalars `s_1, ..., s_u` and return the final
/// BIP-340 64-byte signature `(R_x, s)` where `s = Σ s_i mod n`.
pub fn aggregate_and_finalize(
    agg_nonce: &AggNonce,
    ctx: &KeyAggCtx,
    msg: &[u8; 32],
    partials: &[[u8; 32]],
) -> Result<[u8; 64], Bip327Error> {
    let sv = session_values(agg_nonce, ctx, msg)?;

    // s = Σ s_i mod n (with no e·g·tweak adjustment since we have no tweaks).
    let mut s: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    for partial in partials {
        s = add_mod_n(&s, partial)?;
    }

    // Final BIP-340 signature: (R_x || s). The `s` is public output once
    // released, so the copy out of `Zeroizing` is intentional.
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&sv.r.serialize()[1..]);
    sig[32..].copy_from_slice(&*s);
    Ok(sig)
}

/// Compute the public point `r·G` for a scalar (helper for nonce derivation).
pub fn point_from_scalar(scalar: &SecretKey) -> PublicKey {
    PublicKey::from_secret_key(secp(), scalar)
}

/// BIP-327 §"PartialSigVerify". Returns `Ok(())` iff the supplied
/// `partial_sig` is the partial signature of `signer_pk` over `msg` against
/// the supplied `agg_nonce` and `signer_pubnonce`.
///
/// `sign_epoch` and `operator_partial` use this to validate the participant's
/// pre-signed contribution **before** the operator commits its own VON-bound
/// `(r₁, r₂)` to a partial signature on this `agg_nonce`. Without that
/// check, a malicious participant who submits a valid `pub_nonce` plus a
/// bogus `partial_sig` can either (a) burn the operator's pre-committed
/// nonce slot via an unverifiable aggregate, or (b) coerce the operator
/// into a retry that leaks `sk_op` via two-sigs-same-nonce recovery.
pub fn partial_sig_verify(
    ctx: &KeyAggCtx,
    agg_nonce: &AggNonce,
    msg: &[u8; 32],
    signer_pk: &PublicKey,
    signer_pubnonce: &crate::nonces::PubNonce,
    partial_sig: &[u8; 32],
) -> Result<(), Bip327Error> {
    // s must be in [0, n).
    let s_scalar =
        Scalar::from_be_bytes(*partial_sig).map_err(|_| Bip327Error::PartialSignatureOutOfRange)?;

    let sv = session_values(agg_nonce, ctx, msg)?;

    // R_p = R_s_1 + b · R_s_2 with G fallback per BIP-327.
    let r_s_2_b = signer_pubnonce
        .r2
        .mul_tweak(secp(), &sv.b)
        .map_err(|_| Bip327Error::ScalarZero)?;
    let r_p_raw = match signer_pubnonce.r1.combine(&r_s_2_b) {
        Ok(p) => p,
        Err(_) => *generator(),
    };

    // R-parity flip: if R has odd y, negate R_p.
    let r_p = if has_even_y(&sv.r) {
        r_p_raw
    } else {
        r_p_raw.negate(secp())
    };

    // Key-agg coefficient for this signer.
    let a = key_agg_coeff(ctx, signer_pk)?;

    // Q-parity flip: pk_eff = pk if Q even-y else -pk.
    let pk_eff = if ctx.q_has_even_y() {
        *signer_pk
    } else {
        signer_pk.negate(secp())
    };

    // expected = R_p + (e · a) · pk_eff
    let e_a = e_times_a(&sv.e, &a)?;
    let e_a_pk_eff = pk_eff
        .mul_tweak(secp(), &e_a)
        .map_err(|_| Bip327Error::ScalarZero)?;
    let expected = r_p
        .combine(&e_a_pk_eff)
        .map_err(|_| Bip327Error::AggregateInfinity)?;

    // actual = s · G. If s = 0, expected must also be identity, which we
    // can't represent — reject.
    if partial_sig == &[0u8; 32] {
        return Err(Bip327Error::InvalidPartialSignature);
    }
    let actual = generator()
        .mul_tweak(secp(), &s_scalar)
        .map_err(|_| Bip327Error::ScalarZero)?;

    if actual == expected {
        Ok(())
    } else {
        Err(Bip327Error::InvalidPartialSignature)
    }
}
