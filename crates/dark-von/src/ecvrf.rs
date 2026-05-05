//! ECVRF on secp256k1 with ciphersuite `DARK-VRF-SECP256K1-SHA256-TAI`.
//!
//! See `docs/adr/0006-ecvrf-dependency-strategy.md` for the dependency
//! decision and the precise ciphersuite definition. The construction
//! is RFC 9381 §5 with the byte-level encoding choices documented in
//! that ADR's "Ciphersuite" section.
//!
//! This module intentionally uses the **TAI** (try-and-increment)
//! hash-to-curve variant, not SSWU. RFC 9381 permits both patterns,
//! and ADR-0006 chose TAI because `alpha` is public schedule input in
//! PSAR, making the non-constant-time retry loop acceptable while
//! keeping the implementation small and entirely on `secp256k1 = 0.29`.
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
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;
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
///
/// Serde uses the canonical wire format from [`Proof::to_bytes`].
/// Human-readable serializers (for example JSON) encode proofs as a
/// lowercase hex string; binary serializers use the raw 81-byte form.
///
/// The canonical textual representation is the lowercase hex encoding of
/// the 81-byte wire format. [`Display`] emits that string, and [`FromStr`]
/// parses it via [`Proof::from_hex`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    gamma: PublicKey,
    c: [u8; C_LEN],
    s: [u8; 32],
}

/// Parse errors for [`Proof::from_hex`] and [`FromStr`] on [`Proof`].
#[derive(Debug)]
pub enum ParseProofError {
    /// The input string contained a non-hex character or odd nibble count.
    InvalidHex(&'static str),
    /// The decoded byte sequence was not a valid ECVRF proof.
    InvalidProof(EcvrfError),
}

impl fmt::Display for ParseProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex(msg) => f.write_str(msg),
            Self::InvalidProof(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ParseProofError {}

impl From<EcvrfError> for ParseProofError {
    fn from(err: EcvrfError) -> Self {
        Self::InvalidProof(err)
    }
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Proof {
    type Err = ParseProofError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&encode_hex(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProofVisitor;

        impl<'de> Visitor<'de> for ProofVisitor {
            type Value = Proof;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an 81-byte ECVRF proof or its lowercase hex encoding")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Proof::from_slice(v).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_bytes(&v)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::with_capacity(PROOF_LEN);
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                self.visit_byte_buf(bytes)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Proof::from_hex(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(ProofVisitor)
        } else {
            deserializer.deserialize_bytes(ProofVisitor)
        }
    }
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

    /// Serialise to the canonical lowercase hex form.
    ///
    /// This is the same representation used by human-readable serde
    /// encoders and by [`Display`].
    pub fn to_hex(&self) -> String {
        encode_hex(&self.to_bytes())
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

    /// Parse from the canonical lowercase or uppercase hex form.
    ///
    /// ```
    /// use dark_von::ecvrf::{keygen, prove, Proof};
    /// use rand::{rngs::StdRng, SeedableRng};
    ///
    /// let mut rng = StdRng::seed_from_u64(11);
    /// let kp = keygen(&mut rng);
    /// let (_beta, proof) = prove(&kp.secret, b"serde")?;
    /// let encoded = proof.to_hex();
    /// let decoded = Proof::from_hex(&encoded)?;
    /// assert_eq!(decoded, proof);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self, ParseProofError> {
        let bytes = decode_hex(hex).map_err(ParseProofError::InvalidHex)?;
        Self::from_slice(&bytes).map_err(ParseProofError::from)
    }
}

/// Generate a fresh keypair from `rng`.
pub fn keygen<R: rand::Rng + ?Sized>(rng: &mut R) -> KeyPair {
    let (secret, public) = secp().generate_keypair(rng);
    KeyPair { secret, public }
}

/// Prove `(beta, pi)` for input `alpha` under secret key `sk`.
///
/// ```
/// use dark_von::ecvrf::{keygen, prove, verify};
/// use rand::{rngs::StdRng, SeedableRng};
///
/// let mut rng = StdRng::seed_from_u64(7);
/// let kp = keygen(&mut rng);
/// let alpha = b"cohort-17/slot-3";
/// let (beta, proof) = prove(&kp.secret, alpha)?;
/// verify(&kp.public, alpha, &beta, &proof)?;
/// # Ok::<(), dark_von::EcvrfError>(())
/// ```
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

fn encode_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex proof must have even length");
    }

    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = decode_hex_nibble(bytes[i]).ok_or("hex proof contains non-hex characters")?;
        let lo = decode_hex_nibble(bytes[i + 1]).ok_or("hex proof contains non-hex characters")?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
    fn round_trip_random_1000() {
        let mut rng = StdRng::seed_from_u64(0x5eed_f00d);
        for _ in 0..1000 {
            let kp = keygen(&mut rng);
            let alpha_len = rng.gen_range(0..=512);
            let alpha: Vec<u8> = (0..alpha_len).map(|_| rng.gen()).collect();
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
    fn proof_display_and_from_str_round_trip() {
        let mut rng = StdRng::seed_from_u64(8_675_309);
        let kp = keygen(&mut rng);
        let (_beta, pi) = prove(&kp.secret, b"display").unwrap();

        let encoded = pi.to_string();
        assert_eq!(encoded, pi.to_hex());

        let decoded = Proof::from_str(&encoded).unwrap();
        assert_eq!(decoded, pi);
    }

    #[test]
    fn proof_from_str_rejects_invalid_hex() {
        let err = Proof::from_str("xyz").unwrap_err();
        assert!(matches!(
            err,
            ParseProofError::InvalidHex("hex proof must have even length")
        ));
    }

    #[test]
    fn proof_from_str_rejects_invalid_proof_bytes() {
        let err = Proof::from_str(&"00".repeat(PROOF_LEN)).unwrap_err();
        assert!(matches!(
            err,
            ParseProofError::InvalidProof(EcvrfError::MalformedProofGamma)
        ));
    }

    #[test]
    fn proof_serde_json_round_trip() {
        let mut rng = StdRng::seed_from_u64(9);
        let kp = keygen(&mut rng);
        let (_beta, pi) = prove(&kp.secret, b"serde-json").unwrap();

        let json = serde_json::to_string(&pi).unwrap();
        let encoded = pi.to_hex();
        assert_eq!(json, format!("\"{encoded}\""));

        let decoded: Proof = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, pi);
    }

    #[test]
    fn proof_serde_rejects_invalid_hex() {
        let err = serde_json::from_str::<Proof>("\"xyz\"").unwrap_err();
        assert!(err.to_string().contains("hex proof"));
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
    fn rejects_mutated_proof_gamma() {
        let mut rng = StdRng::seed_from_u64(8);
        let kp = keygen(&mut rng);
        let alpha = b"hello";
        let (beta, pi) = prove(&kp.secret, alpha).unwrap();

        let replacement = loop {
            let candidate = keygen(&mut rng).public.serialize();
            if candidate != pi.gamma().serialize() {
                break candidate;
            }
        };

        let mut bytes = pi.to_bytes();
        bytes[..33].copy_from_slice(&replacement);
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
