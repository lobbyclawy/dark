//! Crate-internal helpers shared between `ecvrf` and `wrapper`.
//!
//! Not part of the public API.

use std::sync::OnceLock;

use secp256k1::{constants::CURVE_ORDER, PublicKey, Scalar, Secp256k1, SecretKey};

/// Process-wide secp256k1 context. `OnceLock` so context precomputation
/// happens at most once per process; matches the cost we want to amortise
/// in benchmarks (#658).
pub(crate) fn secp() -> &'static Secp256k1<secp256k1::All> {
    static S: OnceLock<Secp256k1<secp256k1::All>> = OnceLock::new();
    S.get_or_init(Secp256k1::new)
}

/// secp256k1 generator `G`. Used by `ecvrf::verify` for the `s·G − c·pk` term.
pub(crate) fn generator() -> &'static PublicKey {
    static G: OnceLock<PublicKey> = OnceLock::new();
    G.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        let one = SecretKey::from_slice(&bytes).expect("1 is a valid secret key");
        PublicKey::from_secret_key(secp(), &one)
    })
}

/// `bits2octets(input) = int2octets(bits2int(input) mod q)` per RFC 6979 §2.3.4.
///
/// For secp256k1 (`qLen = 256` bits) and SHA-256 output (256 bits),
/// `bits2int(input)` is just the big-endian interpretation of `input`.
/// We need to reduce mod `n` (the curve order). If `input < n`, return as-is;
/// otherwise subtract `n` once. `input < 2 * n` always (since `n > 2^255`),
/// so a single subtraction suffices.
pub(crate) fn bits2octets_mod_q(input: &[u8; 32]) -> [u8; 32] {
    if Scalar::from_be_bytes(*input).is_ok() {
        *input
    } else {
        sub_q(input)
    }
}

fn sub_q(input: &[u8; 32]) -> [u8; 32] {
    let q = CURVE_ORDER;
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = i16::from(input[i]) - i16::from(q[i]) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }
    result
}

/// Constant-time byte-slice equality. Length-leak is acceptable for our
/// fixed-size inputs (`c: 16 B`, `beta: 32 B`).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (ai, bi) in a.iter().zip(b.iter()) {
        x |= ai ^ bi;
    }
    x == 0
}
