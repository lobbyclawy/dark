//! VON nonce-derivation wrapper.
//!
//! Implements the construction pinned in
//! `docs/adr/0007-von-wrapper-construction.md`:
//!
//! ```text
//! VON.Nonce(sk, x):
//!     r       = HMAC_SHA256(sk_bytes, R_DERIVATION_TAG || x) reduced mod n
//!     R       = r · G
//!     alpha'  = x || compress(R)
//!     (_, π)  = ECVRF.prove(sk, alpha')
//!     return (r, R, π)
//!
//! VON.Verify(pk, x, R, π):
//!     alpha'  = x || compress(R)
//!     β       = ECVRF.proof_to_hash(π)
//!     return ECVRF.verify(pk, alpha', β, π)
//! ```
//!
//! `r` is hidden from verifiers (HMAC under `sk`); `R` is canonical
//! per `(sk, x)` (HMAC + RFC 6979 are deterministic); the ECVRF proof
//! over `alpha' = x || R` binds the published `R` to the keypair and
//! input. Equivocation is observable but not key-extractable — see
//! ADR-0007 §"Equivocation".

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::ecvrf::{self, Proof};
use crate::error::{EcvrfError, VonError};
use crate::internal::{bits2octets_mod_q, secp};

/// Domain separator for `H_r`. Pinned by ADR-0007.
pub const R_DERIVATION_TAG: &[u8] = b"DARK-VON-r-v1";

/// VON keypair. Identical underlying types to `ecvrf::KeyPair` — the
/// wrapper does not re-derive a separate keypair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// Output of [`nonce`]: hidden scalar `r`, public point `R = r·G`, and
/// the ECVRF binding proof `π`.
///
/// `r` is a [`SecretKey`], which auto-zeroizes on drop in
/// `secp256k1 = 0.29` (verified via the upstream `Drop` impl).
#[derive(Clone, Debug)]
pub struct Nonce {
    pub r: SecretKey,
    pub r_point: PublicKey,
    pub proof: Proof,
}

/// Generate a fresh VON keypair.
pub fn keygen<R: rand::Rng + ?Sized>(rng: &mut R) -> KeyPair {
    let kp = ecvrf::keygen(rng);
    KeyPair {
        secret: kp.secret,
        public: kp.public,
    }
}

/// Derive `(r, R, π)` for input `x` under secret key `sk`.
pub fn nonce(sk: &SecretKey, x: &[u8]) -> Result<Nonce, VonError> {
    let r = derive_r(sk, x)?;
    let r_point = PublicKey::from_secret_key(secp(), &r);
    let alpha_prime = build_alpha_prime(x, &r_point);
    let (_beta, proof) = ecvrf::prove(sk, &alpha_prime)?;
    Ok(Nonce { r, r_point, proof })
}

/// Verify that `R` and `π` bind to `(pk, x)`. `Ok(())` on success.
pub fn verify(
    pk: &PublicKey,
    x: &[u8],
    r_point: &PublicKey,
    proof: &Proof,
) -> Result<(), VonError> {
    let alpha_prime = build_alpha_prime(x, r_point);
    let beta = ecvrf::proof_to_hash(proof);
    ecvrf::verify(pk, &alpha_prime, &beta, proof).map_err(|e| match e {
        EcvrfError::VerificationFailed => VonError::WrongPublicKey,
        other => VonError::Ecvrf(other),
    })
}

fn build_alpha_prime(x: &[u8], r_point: &PublicKey) -> Vec<u8> {
    let mut buf = Vec::with_capacity(x.len() + 33);
    buf.extend_from_slice(x);
    buf.extend_from_slice(&r_point.serialize());
    buf
}

fn derive_r(sk: &SecretKey, x: &[u8]) -> Result<SecretKey, VonError> {
    let key = Zeroizing::new(sk.secret_bytes());
    for ctr in 0u8..=255 {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&*key).expect("HMAC accepts any key length");
        mac.update(R_DERIVATION_TAG);
        mac.update(x);
        if ctr > 0 {
            mac.update(&[ctr]);
        }
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        let reduced = bits2octets_mod_q(&digest);
        if let Ok(r) = SecretKey::from_slice(&reduced) {
            return Ok(r);
        }
    }
    Err(VonError::ScalarZero)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn round_trip_random_64() {
        let mut rng = StdRng::seed_from_u64(0xfeed_face);
        for _ in 0..64 {
            let kp = keygen(&mut rng);
            let mut x = [0u8; 32];
            rng.fill(&mut x);
            let n = nonce(&kp.secret, &x).expect("nonce");
            verify(&kp.public, &x, &n.r_point, &n.proof).expect("verify");
        }
    }

    #[test]
    fn r_point_equals_r_times_g() {
        let mut rng = StdRng::seed_from_u64(1);
        let kp = keygen(&mut rng);
        let n = nonce(&kp.secret, b"x").unwrap();
        let r_g = PublicKey::from_secret_key(secp(), &n.r);
        assert_eq!(r_g, n.r_point);
    }

    #[test]
    fn deterministic_nonce() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let n1 = nonce(&sk, b"deterministic").unwrap();
        let n2 = nonce(&sk, b"deterministic").unwrap();
        assert_eq!(n1.r.secret_bytes(), n2.r.secret_bytes());
        assert_eq!(n1.r_point, n2.r_point);
        assert_eq!(n1.proof, n2.proof);
    }

    #[test]
    fn distinct_x_distinct_r() {
        let sk = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let n1 = nonce(&sk, b"x1").unwrap();
        let n2 = nonce(&sk, b"x2").unwrap();
        assert_ne!(n1.r_point, n2.r_point);
    }

    #[test]
    fn distinct_sk_distinct_r_for_same_x() {
        let sk_a = SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let sk_b = SecretKey::from_slice(&[0x22u8; 32]).unwrap();
        let n_a = nonce(&sk_a, b"shared").unwrap();
        let n_b = nonce(&sk_b, b"shared").unwrap();
        assert_ne!(n_a.r_point, n_b.r_point);
    }

    #[test]
    fn wrong_public_key_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let kp = keygen(&mut rng);
        let kp2 = keygen(&mut rng);
        let n = nonce(&kp.secret, b"x").unwrap();
        let result = verify(&kp2.public, b"x", &n.r_point, &n.proof);
        assert!(matches!(result, Err(VonError::WrongPublicKey)));
    }

    #[test]
    fn mutated_x_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let kp = keygen(&mut rng);
        let n = nonce(&kp.secret, b"abc").unwrap();
        let result = verify(&kp.public, b"abd", &n.r_point, &n.proof);
        assert!(matches!(result, Err(VonError::WrongPublicKey)));
    }

    #[test]
    fn mutated_r_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let kp = keygen(&mut rng);
        let n = nonce(&kp.secret, b"x").unwrap();
        let other = nonce(&kp.secret, b"y").unwrap();
        let result = verify(&kp.public, b"x", &other.r_point, &n.proof);
        assert!(matches!(result, Err(VonError::WrongPublicKey)));
    }

    #[test]
    fn mutated_proof_rejected() {
        let mut rng = StdRng::seed_from_u64(5);
        let kp = keygen(&mut rng);
        let n = nonce(&kp.secret, b"x").unwrap();
        let mut bytes = n.proof.to_bytes();
        bytes[80] ^= 0x01;
        let mutated = Proof::from_slice(&bytes).expect("still parseable");
        let result = verify(&kp.public, b"x", &n.r_point, &mutated);
        assert!(matches!(result, Err(VonError::WrongPublicKey)));
    }

    #[test]
    fn two_of_two_distinct_b_field() {
        // Issue #655 acceptance: 2-of-2 distinct nonces.
        // Simulates MuSig2's b ∈ {1, 2} via a one-byte suffix on `x`.
        let sk = SecretKey::from_slice(&[0x33u8; 32]).unwrap();
        let mut x_base = b"setup||t".to_vec();
        x_base.push(1);
        let n_b1 = nonce(&sk, &x_base).unwrap();
        x_base.pop();
        x_base.push(2);
        let n_b2 = nonce(&sk, &x_base).unwrap();
        assert_ne!(n_b1.r_point, n_b2.r_point);
        assert_ne!(n_b1.r.secret_bytes(), n_b2.r.secret_bytes());
        assert_ne!(n_b1.proof, n_b2.proof);
    }

    #[test]
    fn r_derivation_tag_value() {
        assert_eq!(R_DERIVATION_TAG, b"DARK-VON-r-v1");
    }

    #[test]
    fn empty_x_round_trip() {
        let sk = SecretKey::from_slice(&[0x77u8; 32]).unwrap();
        let n = nonce(&sk, &[]).unwrap();
        let pk = PublicKey::from_secret_key(secp(), &sk);
        verify(&pk, &[], &n.r_point, &n.proof).unwrap();
    }

    #[test]
    fn alpha_prime_layout_x_then_r() {
        // Confirm alpha' = x || R_compressed by inspecting that the same
        // x with two different R values produces two distinct ECVRF inputs
        // (and therefore distinct β).
        let sk = SecretKey::from_slice(&[0x55u8; 32]).unwrap();
        let n1 = nonce(&sk, b"x").unwrap();
        // Synthesize an alternative `R'` (use a different sk's R for the same x).
        let sk2 = SecretKey::from_slice(&[0x66u8; 32]).unwrap();
        let n2 = nonce(&sk2, b"x").unwrap();
        // Verify that swapping R_point breaks verification (since alpha' changes).
        assert!(matches!(
            verify(
                &PublicKey::from_secret_key(secp(), &sk),
                b"x",
                &n2.r_point,
                &n1.proof
            ),
            Err(VonError::WrongPublicKey)
        ));
    }
}
