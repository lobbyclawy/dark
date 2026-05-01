//! ECVRF on secp256k1 with ciphersuite `DARK-VRF-SECP256K1-SHA256-TAI`.
//!
//! See `docs/adr/0006-ecvrf-dependency-strategy.md` for the dependency
//! decision and the precise ciphersuite definition. The construction
//! is RFC 9381 §5 with the byte-level encoding choices documented in
//! that ADR's "Ciphersuite" section.
//!
//! Surface:
//!
//! - [`keygen`], [`prove`], [`verify`]
//! - [`KeyPair`], [`Proof`]
//! - [`SUITE_STRING`], [`PROOF_LEN`]
//!
//! `prove` and `verify` are deterministic in `(sk, alpha)` (nonce
//! generation per RFC 6979 §3.2 over `(sk, H(point_to_string(H)))`,
//! per RFC 9381 §5.4.2.2).

use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::EcvrfError;
use crate::internal::{bits2octets_mod_q, ct_eq, generator, secp};

/// Ciphersuite identifier per ADR-0006.
pub const SUITE_STRING: &[u8] = b"DARK-VRF-SECP256K1-SHA256-TAI";

/// Wire length of an [`Proof`] when serialised via [`Proof::to_bytes`].
///
/// Layout: `gamma (33 B compressed) || c (16 B) || s (32 B BE)`.
pub const PROOF_LEN: usize = 81;

const HTC_FRONT: u8 = 0x01;
const HTC_BACK: u8 = 0x00;
const CHALLENGE_FRONT: u8 = 0x02;
const CHALLENGE_BACK: u8 = 0x00;
const PROOF_TO_HASH_FRONT: u8 = 0x03;
const PROOF_TO_HASH_BACK: u8 = 0x00;

const C_LEN: usize = 16;

/// ECVRF keypair.
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

/// ECVRF proof: `(Gamma, c, s)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    gamma: PublicKey,
    c: [u8; C_LEN],
    s: [u8; 32],
}

impl Proof {
    /// `Gamma` point. Exposed so callers (e.g. the VON wrapper, #655)
    /// can reuse it without re-running `hash_to_curve`.
    pub fn gamma(&self) -> &PublicKey {
        &self.gamma
    }

    /// Truncated challenge scalar (16 bytes BE, conventionally interpreted
    /// as a 256-bit scalar with high 16 bytes zero).
    pub fn c(&self) -> &[u8; C_LEN] {
        &self.c
    }

    /// Response scalar `s ∈ [0, n)` as 32 bytes BE.
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Serialise to the canonical 81-byte wire form.
    pub fn to_bytes(&self) -> [u8; PROOF_LEN] {
        let mut out = [0u8; PROOF_LEN];
        out[..33].copy_from_slice(&self.gamma.serialize());
        out[33..49].copy_from_slice(&self.c);
        out[49..81].copy_from_slice(&self.s);
        out
    }

    /// Parse from the canonical 81-byte wire form.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EcvrfError> {
        if bytes.len() != PROOF_LEN {
            return Err(EcvrfError::MalformedProofLength {
                expected: PROOF_LEN,
                got: bytes.len(),
            });
        }
        let gamma =
            PublicKey::from_slice(&bytes[..33]).map_err(|_| EcvrfError::MalformedProofGamma)?;
        let mut c = [0u8; C_LEN];
        c.copy_from_slice(&bytes[33..49]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[49..81]);
        Scalar::from_be_bytes(s).map_err(|_| EcvrfError::MalformedProofScalar)?;
        Ok(Proof { gamma, c, s })
    }
}

/// Generate a fresh keypair from `rng`.
pub fn keygen<R: rand::Rng + ?Sized>(rng: &mut R) -> KeyPair {
    let (secret, public) = secp().generate_keypair(rng);
    KeyPair { secret, public }
}

/// Prove `(beta, pi)` for input `alpha` under secret key `sk`.
pub fn prove(sk: &SecretKey, alpha: &[u8]) -> Result<([u8; 32], Proof), EcvrfError> {
    let secp = secp();
    let pk = PublicKey::from_secret_key(secp, sk);
    let h = hash_to_curve(&pk, alpha)?;

    let sk_scalar = scalar_from_secret_key(sk);
    let gamma = h
        .mul_tweak(secp, &sk_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;

    let k_sk = nonce_rfc6979(sk, &h)?;
    let k_g = PublicKey::from_secret_key(secp, &k_sk);
    let k_scalar = scalar_from_secret_key(&k_sk);
    let k_h = h
        .mul_tweak(secp, &k_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;

    let c = challenge(&pk, &h, &gamma, &k_g, &k_h);

    let c_scalar = pad_c_to_scalar(&c);
    let cs_sk = sk
        .mul_tweak(&c_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;
    let cs_scalar = scalar_from_secret_key(&cs_sk);
    let s_sk = k_sk
        .add_tweak(&cs_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;

    let proof = Proof {
        gamma,
        c,
        s: s_sk.secret_bytes(),
    };
    let beta = proof_to_hash(&proof);
    Ok((beta, proof))
}

/// Verify `pi` against `(pk, alpha, beta)`. Returns `Ok(())` on success.
pub fn verify(pk: &PublicKey, alpha: &[u8], beta: &[u8; 32], pi: &Proof) -> Result<(), EcvrfError> {
    let secp = secp();
    let h = hash_to_curve(pk, alpha)?;

    let s_scalar = Scalar::from_be_bytes(pi.s).map_err(|_| EcvrfError::MalformedProofScalar)?;
    let c_scalar = pad_c_to_scalar(&pi.c);

    let s_g = generator()
        .mul_tweak(secp, &s_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;
    let c_pk = pk
        .mul_tweak(secp, &c_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;
    let neg_c_pk = c_pk.negate(secp);
    let u = s_g
        .combine(&neg_c_pk)
        .map_err(|_| EcvrfError::VerificationFailed)?;

    let s_h = h
        .mul_tweak(secp, &s_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;
    let c_gamma = pi
        .gamma
        .mul_tweak(secp, &c_scalar)
        .map_err(|_| EcvrfError::ScalarZero)?;
    let neg_c_gamma = c_gamma.negate(secp);
    let v = s_h
        .combine(&neg_c_gamma)
        .map_err(|_| EcvrfError::VerificationFailed)?;

    let c_prime = challenge(pk, &h, &pi.gamma, &u, &v);
    if !ct_eq(&c_prime, &pi.c) {
        return Err(EcvrfError::VerificationFailed);
    }
    let beta_prime = proof_to_hash(pi);
    if !ct_eq(beta, &beta_prime) {
        return Err(EcvrfError::VerificationFailed);
    }
    Ok(())
}

/// `proof_to_hash` per RFC 9381 §5.2 (cofactor = 1 on secp256k1).
pub fn proof_to_hash(proof: &Proof) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SUITE_STRING);
    hasher.update([PROOF_TO_HASH_FRONT]);
    hasher.update(proof.gamma.serialize());
    hasher.update([PROOF_TO_HASH_BACK]);
    hasher.finalize().into()
}

fn hash_to_curve(pk: &PublicKey, alpha: &[u8]) -> Result<PublicKey, EcvrfError> {
    let pk_string = pk.serialize();
    for ctr in 0u8..=255 {
        let mut hasher = Sha256::new();
        hasher.update(SUITE_STRING);
        hasher.update([HTC_FRONT]);
        hasher.update(pk_string);
        hasher.update(alpha);
        hasher.update([ctr]);
        hasher.update([HTC_BACK]);
        let digest: [u8; 32] = hasher.finalize().into();

        let mut buf = [0u8; 33];
        buf[0] = 0x02;
        buf[1..].copy_from_slice(&digest);
        if let Ok(point) = PublicKey::from_slice(&buf) {
            return Ok(point);
        }
    }
    Err(EcvrfError::HashToCurveExhausted)
}

fn challenge(
    pk: &PublicKey,
    h: &PublicKey,
    gamma: &PublicKey,
    u: &PublicKey,
    v: &PublicKey,
) -> [u8; C_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(SUITE_STRING);
    hasher.update([CHALLENGE_FRONT]);
    hasher.update(pk.serialize());
    hasher.update(h.serialize());
    hasher.update(gamma.serialize());
    hasher.update(u.serialize());
    hasher.update(v.serialize());
    hasher.update([CHALLENGE_BACK]);
    let digest: [u8; 32] = hasher.finalize().into();

    let mut c = [0u8; C_LEN];
    c.copy_from_slice(&digest[..C_LEN]);
    c
}

fn nonce_rfc6979(sk: &SecretKey, h: &PublicKey) -> Result<SecretKey, EcvrfError> {
    let h_string = h.serialize();
    let x_octets = Zeroizing::new(sk.secret_bytes());

    let h1: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(h_string);
        hasher.finalize().into()
    };
    let h1_octets = bits2octets_mod_q(&h1);

    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    let mut buf = Zeroizing::new(Vec::with_capacity(32 + 1 + 32 + 32));
    buf.extend_from_slice(&v);
    buf.push(0x00);
    buf.extend_from_slice(&*x_octets);
    buf.extend_from_slice(&h1_octets);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    buf.clear();
    buf.extend_from_slice(&v);
    buf.push(0x01);
    buf.extend_from_slice(&*x_octets);
    buf.extend_from_slice(&h1_octets);
    k = hmac_sha256(&k, &buf);
    v = hmac_sha256(&k, &v);

    for _ in 0..1024 {
        v = hmac_sha256(&k, &v);
        if let Ok(sk) = SecretKey::from_slice(&v) {
            return Ok(sk);
        }
        let mut tail = Vec::with_capacity(33);
        tail.extend_from_slice(&v);
        tail.push(0x00);
        k = hmac_sha256(&k, &tail);
        v = hmac_sha256(&k, &v);
    }
    Err(EcvrfError::Rfc6979Exhausted)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn scalar_from_secret_key(sk: &SecretKey) -> Scalar {
    Scalar::from_be_bytes(sk.secret_bytes())
        .expect("SecretKey bytes are always a valid non-zero curve scalar")
}

fn pad_c_to_scalar(c: &[u8; C_LEN]) -> Scalar {
    let mut padded = [0u8; 32];
    padded[16..].copy_from_slice(c);
    Scalar::from_be_bytes(padded).expect("16-byte value is always less than n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn round_trip_random_64() {
        let mut rng = StdRng::seed_from_u64(0xdead_beef);
        for _ in 0..64 {
            let kp = keygen(&mut rng);
            let mut alpha = [0u8; 32];
            rng.fill(&mut alpha);
            let (beta, pi) = prove(&kp.secret, &alpha).expect("prove");
            verify(&kp.public, &alpha, &beta, &pi).expect("verify");
        }
    }

    #[test]
    fn proof_byte_round_trip() {
        let mut rng = StdRng::seed_from_u64(1);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (_beta, pi) = prove(&kp.secret, alpha).unwrap();
        let bytes = pi.to_bytes();
        assert_eq!(bytes.len(), PROOF_LEN);
        let pi2 = Proof::from_slice(&bytes).unwrap();
        assert_eq!(pi, pi2);
    }

    #[test]
    fn rejects_wrong_public_key() {
        let mut rng = StdRng::seed_from_u64(2);
        let kp = keygen(&mut rng);
        let kp2 = keygen(&mut rng);
        let alpha = b"hello";
        let (beta, pi) = prove(&kp.secret, alpha).unwrap();
        let result = verify(&kp2.public, alpha, &beta, &pi);
        assert!(matches!(result, Err(EcvrfError::VerificationFailed)));
    }

    #[test]
    fn rejects_mutated_alpha() {
        let mut rng = StdRng::seed_from_u64(3);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (beta, pi) = prove(&kp.secret, alpha).unwrap();
        let result = verify(&kp.public, b"hellp", &beta, &pi);
        assert!(matches!(result, Err(EcvrfError::VerificationFailed)));
    }

    #[test]
    fn rejects_mutated_proof_s() {
        let mut rng = StdRng::seed_from_u64(4);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (beta, pi) = prove(&kp.secret, alpha).unwrap();
        let mut bytes = pi.to_bytes();
        bytes[80] ^= 0x01;
        let pi_mut = Proof::from_slice(&bytes).unwrap();
        let result = verify(&kp.public, alpha, &beta, &pi_mut);
        assert!(matches!(result, Err(EcvrfError::VerificationFailed)));
    }

    #[test]
    fn rejects_mutated_proof_c() {
        let mut rng = StdRng::seed_from_u64(5);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (beta, pi) = prove(&kp.secret, alpha).unwrap();
        let mut bytes = pi.to_bytes();
        bytes[40] ^= 0x01;
        let pi_mut = Proof::from_slice(&bytes).unwrap();
        let result = verify(&kp.public, alpha, &beta, &pi_mut);
        assert!(matches!(result, Err(EcvrfError::VerificationFailed)));
    }

    #[test]
    fn rejects_mutated_beta() {
        let mut rng = StdRng::seed_from_u64(6);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (mut beta, pi) = prove(&kp.secret, alpha).unwrap();
        beta[0] ^= 0x01;
        let result = verify(&kp.public, alpha, &beta, &pi);
        assert!(matches!(result, Err(EcvrfError::VerificationFailed)));
    }

    #[test]
    fn rejects_malformed_proof_length() {
        assert!(matches!(
            Proof::from_slice(&[0u8; 80]),
            Err(EcvrfError::MalformedProofLength {
                expected: 81,
                got: 80
            })
        ));
    }

    #[test]
    fn rejects_malformed_proof_gamma() {
        let mut bytes = [0u8; PROOF_LEN];
        bytes[0] = 0x02;
        assert!(matches!(
            Proof::from_slice(&bytes),
            Err(EcvrfError::MalformedProofGamma)
        ));
    }

    #[test]
    fn deterministic_prove() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let alpha = b"deterministic";
        let (beta1, pi1) = prove(&sk, alpha).unwrap();
        let (beta2, pi2) = prove(&sk, alpha).unwrap();
        assert_eq!(beta1, beta2);
        assert_eq!(pi1, pi2);
    }

    #[test]
    fn distinct_alpha_distinct_beta() {
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let (b1, _) = prove(&sk, b"a").unwrap();
        let (b2, _) = prove(&sk, b"b").unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn suite_string_value() {
        assert_eq!(SUITE_STRING, b"DARK-VRF-SECP256K1-SHA256-TAI");
    }

    #[test]
    fn proof_len_value() {
        assert_eq!(PROOF_LEN, 81);
    }

    #[test]
    fn random_alpha_lengths() {
        let mut rng = StdRng::seed_from_u64(7);
        for len in [0usize, 1, 32, 33, 64, 100, 256] {
            let kp = keygen(&mut rng);
            let alpha: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let (beta, pi) = prove(&kp.secret, &alpha).unwrap();
            verify(&kp.public, &alpha, &beta, &pi).expect("verify");
        }
    }
}
