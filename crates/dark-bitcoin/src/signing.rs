//! MuSig2 nonce exchange and partial signature aggregation.
//!
//! Implements the signing rounds of BIP-327 MuSig2:
//! 1. **Nonce generation** — each signer generates a secret/public nonce pair
//! 2. **Nonce aggregation** — public nonces are combined into an aggregate nonce
//! 3. **Partial signing** — each signer produces a partial signature
//! 4. **Signature aggregation** — partial signatures are combined into a final
//!    Schnorr signature valid under the aggregated public key
//!
//! This module builds on top of the key aggregation in [`super::tree`].

use musig2::secp256k1::SecretKey;
use musig2::{
    aggregate_partial_signatures, sign_partial, verify_partial, AggNonce, BinaryEncoding,
    CompactSignature, KeyAggContext, PartialSignature, PubNonce, SecNonce,
};

use crate::error::{BitcoinError, BitcoinResult};

/// Generate a MuSig2 secret/public nonce pair for a signing session.
///
/// The nonce is bound to the signer's secret key and the message being signed,
/// which provides protection against nonce-reuse attacks.
///
/// # Arguments
/// * `seckey` - The signer's secret key
/// * `msg` - The message that will be signed (typically a sighash)
///
/// # Returns
/// A tuple of `(SecNonce, PubNonce)`. The `SecNonce` must be kept secret and
/// used exactly once. The `PubNonce` is shared with other signers.
pub fn generate_nonce(seckey: &SecretKey, msg: &[u8]) -> (SecNonce, PubNonce) {
    let mut rng = rand::thread_rng();
    let mut seed_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut seed_bytes);
    let nonce_seed = musig2::NonceSeed(seed_bytes);
    let sec_nonce: SecNonce = SecNonce::build(nonce_seed)
        .with_seckey(*seckey)
        .with_message(&msg)
        .build();
    let pub_nonce = sec_nonce.public_nonce();
    (sec_nonce, pub_nonce)
}

/// Aggregate public nonces from all signing participants.
///
/// # Arguments
/// * `pub_nonces` - Public nonces from each participant
///
/// # Returns
/// The aggregated nonce used in the signing and verification rounds.
pub fn aggregate_nonces(pub_nonces: &[PubNonce]) -> AggNonce {
    AggNonce::sum(pub_nonces)
}

/// Create a MuSig2 partial signature.
///
/// Each signer calls this with their secret key and secret nonce to produce
/// a partial signature. The partial signatures are then aggregated to form
/// the final Schnorr signature.
///
/// # Arguments
/// * `key_agg_ctx` - The key aggregation context (from [`super::tree::aggregate_keys`])
/// * `seckey` - The signer's secret key
/// * `sec_nonce` - The signer's secret nonce (**consumed** — must not be reused)
/// * `agg_nonce` - The aggregated nonce from all participants
/// * `msg` - The 32-byte message being signed (typically a sighash)
///
/// # Errors
/// Returns an error if signing fails (e.g., the secret key is not part of
/// the key aggregation context).
pub fn create_partial_sig(
    key_agg_ctx: &KeyAggContext,
    seckey: &SecretKey,
    sec_nonce: SecNonce,
    agg_nonce: &AggNonce,
    msg: &[u8; 32],
) -> BitcoinResult<PartialSignature> {
    sign_partial(key_agg_ctx, *seckey, sec_nonce, agg_nonce, *msg)
        .map_err(|e| BitcoinError::ScriptError(format!("MuSig2 partial signing failed: {}", e)))
}

/// Verify a MuSig2 partial signature from a co-signer.
///
/// This should be called before aggregating partial signatures to ensure
/// each co-signer's contribution is valid.
///
/// # Arguments
/// * `key_agg_ctx` - The key aggregation context
/// * `partial_sig` - The partial signature to verify
/// * `agg_nonce` - The aggregated nonce
/// * `individual_pubkey` - The co-signer's individual public key
/// * `individual_pubnonce` - The co-signer's individual public nonce
/// * `msg` - The 32-byte message that was signed
///
/// # Errors
/// Returns an error if the partial signature is invalid.
pub fn verify_partial_sig(
    key_agg_ctx: &KeyAggContext,
    partial_sig: PartialSignature,
    agg_nonce: &AggNonce,
    individual_pubkey: musig2::secp256k1::PublicKey,
    individual_pubnonce: &PubNonce,
    msg: &[u8; 32],
) -> BitcoinResult<()> {
    verify_partial(
        key_agg_ctx,
        partial_sig,
        agg_nonce,
        individual_pubkey,
        individual_pubnonce,
        *msg,
    )
    .map_err(|e| {
        BitcoinError::ScriptError(format!(
            "MuSig2 partial signature verification failed: {}",
            e
        ))
    })
}

/// Aggregate partial signatures into a final Schnorr signature.
///
/// Once all signers have contributed valid partial signatures, this function
/// combines them into a single BIP-340 Schnorr signature that is valid under
/// the aggregated public key.
///
/// # Arguments
/// * `key_agg_ctx` - The key aggregation context
/// * `agg_nonce` - The aggregated nonce
/// * `partial_sigs` - Partial signatures from all participants
/// * `msg` - The 32-byte message that was signed
///
/// # Returns
/// A 64-byte compact Schnorr signature.
///
/// # Errors
/// Returns an error if aggregation fails (e.g., invalid partial signatures).
pub fn aggregate_signatures(
    key_agg_ctx: &KeyAggContext,
    agg_nonce: &AggNonce,
    partial_sigs: &[PartialSignature],
    msg: &[u8; 32],
) -> BitcoinResult<[u8; 64]> {
    let sig: CompactSignature =
        aggregate_partial_signatures(key_agg_ctx, agg_nonce, partial_sigs.iter().copied(), *msg)
            .map_err(|e| {
                BitcoinError::ScriptError(format!("MuSig2 signature aggregation failed: {}", e))
            })?;
    Ok(sig.to_bytes())
}

/// Helper: build a [`KeyAggContext`] from musig2-native public keys.
///
/// This is a convenience wrapper used internally and in tests. For the
/// main key aggregation API that works with `bitcoin::XOnlyPublicKey`,
/// see [`super::tree::aggregate_keys`].
pub fn build_key_agg_ctx(pubkeys: &[musig2::secp256k1::PublicKey]) -> BitcoinResult<KeyAggContext> {
    KeyAggContext::new(pubkeys.to_vec())
        .map_err(|e| BitcoinError::ScriptError(format!("MuSig2 key aggregation failed: {}", e)))
}

/// Execute a complete MuSig2 signing session: nonce exchange → partial signing → aggregation.
///
/// This is a convenience function that runs the full protocol for a set of
/// co-signers who are all local (e.g., in tests or single-party scenarios).
///
/// # Arguments
/// * `secret_keys` - Secret keys for all participants
/// * `msg` - The 32-byte message to sign
///
/// # Returns
/// A tuple of `(aggregated_compressed_pubkey_33bytes, signature_64bytes)`.
///
/// # Errors
/// Returns an error if any step of the protocol fails.
pub fn sign_full_session(
    secret_keys: &[SecretKey],
    msg: &[u8; 32],
) -> BitcoinResult<([u8; 33], [u8; 64])> {
    use musig2::secp256k1::{PublicKey, Secp256k1};

    let secp = Secp256k1::new();

    // Derive public keys
    let pubkeys: Vec<PublicKey> = secret_keys
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();

    // Key aggregation
    let key_agg_ctx = build_key_agg_ctx(&pubkeys)?;
    let agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();

    // Round 1: nonce generation
    let nonce_pairs: Vec<(SecNonce, PubNonce)> = secret_keys
        .iter()
        .map(|sk| generate_nonce(sk, msg))
        .collect();

    let pub_nonces: Vec<PubNonce> = nonce_pairs.iter().map(|(_, pn)| pn.clone()).collect();
    let agg_nonce = aggregate_nonces(&pub_nonces);

    // Round 2: partial signing
    let partial_sigs: Vec<PartialSignature> = secret_keys
        .iter()
        .zip(nonce_pairs)
        .map(|(sk, (sec_nonce, _))| {
            create_partial_sig(&key_agg_ctx, sk, sec_nonce, &agg_nonce, msg)
        })
        .collect::<BitcoinResult<Vec<_>>>()?;

    // Aggregation
    let sig = aggregate_signatures(&key_agg_ctx, &agg_nonce, &partial_sigs, msg)?;

    Ok((agg_pubkey.serialize(), sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// Helper: create a deterministic secret key from a byte.
    fn test_seckey(b: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = b;
        SecretKey::from_byte_array(bytes).unwrap()
    }

    /// Helper: derive public key from secret key.
    fn test_pubkey(sk: &SecretKey) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, sk)
    }

    #[test]
    fn nonce_generation_produces_unique_nonces() {
        let sk = test_seckey(1);
        let msg = [0xABu8; 32];

        let (sec1, pub1) = generate_nonce(&sk, &msg);
        let (sec2, pub2) = generate_nonce(&sk, &msg);

        // Nonces must be different each time (randomized)
        assert_ne!(pub1, pub2, "Nonces should be unique due to random seed");
        // SecNonce and PubNonce must be related
        assert_eq!(sec1.public_nonce(), pub1);
        assert_eq!(sec2.public_nonce(), pub2);
    }

    #[test]
    fn two_party_full_signing_flow() {
        let sk1 = test_seckey(1);
        let sk2 = test_seckey(2);
        let pk1 = test_pubkey(&sk1);
        let pk2 = test_pubkey(&sk2);
        let msg = [0x42u8; 32];

        // Key aggregation
        let key_agg_ctx = build_key_agg_ctx(&[pk1, pk2]).unwrap();
        let agg_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

        // Round 1: nonce generation
        let (sec_nonce1, pub_nonce1) = generate_nonce(&sk1, &msg);
        let (sec_nonce2, pub_nonce2) = generate_nonce(&sk2, &msg);

        let agg_nonce = aggregate_nonces(&[pub_nonce1.clone(), pub_nonce2.clone()]);

        // Round 2: partial signing
        let psig1 = create_partial_sig(&key_agg_ctx, &sk1, sec_nonce1, &agg_nonce, &msg).unwrap();
        let psig2 = create_partial_sig(&key_agg_ctx, &sk2, sec_nonce2, &agg_nonce, &msg).unwrap();

        // Verify partial signatures
        verify_partial_sig(&key_agg_ctx, psig1, &agg_nonce, pk1, &pub_nonce1, &msg).unwrap();
        verify_partial_sig(&key_agg_ctx, psig2, &agg_nonce, pk2, &pub_nonce2, &msg).unwrap();

        // Aggregate
        let sig_bytes =
            aggregate_signatures(&key_agg_ctx, &agg_nonce, &[psig1, psig2], &msg).unwrap();

        // Verify the final Schnorr signature
        assert_eq!(sig_bytes.len(), 64);
        let ok = musig2::verify_single(agg_pubkey, sig_bytes, msg);
        assert!(ok.is_ok(), "Final Schnorr signature should be valid");
    }

    #[test]
    fn three_party_signing() {
        let sks: Vec<SecretKey> = (1u8..=3).map(test_seckey).collect();
        let pks: Vec<PublicKey> = sks.iter().map(test_pubkey).collect();
        let msg = [0xFFu8; 32];

        let key_agg_ctx = build_key_agg_ctx(&pks).unwrap();
        let agg_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

        // Round 1
        let nonces: Vec<(SecNonce, PubNonce)> =
            sks.iter().map(|sk| generate_nonce(sk, &msg)).collect();
        let pub_nonces: Vec<PubNonce> = nonces.iter().map(|(_, pn)| pn.clone()).collect();
        let agg_nonce = aggregate_nonces(&pub_nonces);

        // Round 2
        let partial_sigs: Vec<PartialSignature> = sks
            .iter()
            .zip(nonces.into_iter())
            .map(|(sk, (sn, _))| {
                create_partial_sig(&key_agg_ctx, sk, sn, &agg_nonce, &msg).unwrap()
            })
            .collect();

        let sig_bytes =
            aggregate_signatures(&key_agg_ctx, &agg_nonce, &partial_sigs, &msg).unwrap();

        let ok = musig2::verify_single(agg_pubkey, sig_bytes, msg);
        assert!(ok.is_ok(), "3-party signature should verify");
    }

    #[test]
    fn sign_full_session_two_parties() {
        let sks: Vec<SecretKey> = vec![test_seckey(1), test_seckey(2)];
        let msg = [0x77u8; 32];

        let (agg_pk_bytes, sig_bytes) = sign_full_session(&sks, &msg).unwrap();

        assert_eq!(agg_pk_bytes.len(), 33);
        assert_eq!(sig_bytes.len(), 64);

        // Verify with musig2 directly
        let agg_pk = PublicKey::from_slice(&agg_pk_bytes).unwrap();
        let ok = musig2::verify_single(agg_pk, sig_bytes, msg);
        assert!(ok.is_ok(), "Full session signature should verify");
    }

    #[test]
    fn sign_full_session_ten_parties() {
        let sks: Vec<SecretKey> = (1u8..=10).map(test_seckey).collect();
        let msg = [0xBBu8; 32];

        let (agg_pk_bytes, sig_bytes) = sign_full_session(&sks, &msg).unwrap();

        let agg_pk = PublicKey::from_slice(&agg_pk_bytes).unwrap();
        let ok = musig2::verify_single(agg_pk, sig_bytes, msg);
        assert!(ok.is_ok(), "10-party full session signature should verify");
    }

    #[test]
    fn invalid_partial_sig_is_rejected() {
        let sk1 = test_seckey(1);
        let sk2 = test_seckey(2);
        let pk1 = test_pubkey(&sk1);
        let pk2 = test_pubkey(&sk2);
        let msg = [0x99u8; 32];

        let key_agg_ctx = build_key_agg_ctx(&[pk1, pk2]).unwrap();

        let (sec_nonce1, pub_nonce1) = generate_nonce(&sk1, &msg);
        let (_, pub_nonce2) = generate_nonce(&sk2, &msg);

        let agg_nonce = aggregate_nonces(&[pub_nonce1.clone(), pub_nonce2.clone()]);

        // Create a valid partial sig from sk1
        let psig1 = create_partial_sig(&key_agg_ctx, &sk1, sec_nonce1, &agg_nonce, &msg).unwrap();

        // Verify psig1 against pk2's identity — should fail
        let result = verify_partial_sig(&key_agg_ctx, psig1, &agg_nonce, pk2, &pub_nonce2, &msg);
        assert!(
            result.is_err(),
            "Partial sig from sk1 should not verify against pk2's nonce"
        );
    }

    #[test]
    fn nonce_aggregation_is_deterministic() {
        let sk1 = test_seckey(1);
        let sk2 = test_seckey(2);
        let msg = [0x11u8; 32];

        let (_, pn1) = generate_nonce(&sk1, &msg);
        let (_, pn2) = generate_nonce(&sk2, &msg);

        let agg1 = aggregate_nonces(&[pn1.clone(), pn2.clone()]);
        let agg2 = aggregate_nonces(&[pn1.clone(), pn2.clone()]);
        assert_eq!(agg1, agg2, "Same nonces should produce same aggregate");
    }

    #[test]
    fn different_messages_produce_different_signatures() {
        let sks: Vec<SecretKey> = vec![test_seckey(1), test_seckey(2)];
        let msg1 = [0xAAu8; 32];
        let msg2 = [0xBBu8; 32];

        let (_, sig1) = sign_full_session(&sks, &msg1).unwrap();
        let (_, sig2) = sign_full_session(&sks, &msg2).unwrap();

        assert_ne!(sig1, sig2, "Different messages must produce different sigs");
    }
}
