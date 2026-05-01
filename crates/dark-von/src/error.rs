//! Crate-level error types.
//!
//! Per `docs/conventions/errors.md`: per-module enums with structured
//! variants, `#[non_exhaustive]`, lowercase sentence-form messages.

use thiserror::Error;

/// Errors raised by the `ecvrf` module.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EcvrfError {
    #[error("malformed proof: expected {expected} bytes, got {got}")]
    MalformedProofLength { expected: usize, got: usize },

    #[error("malformed proof: gamma is not a valid secp256k1 point")]
    MalformedProofGamma,

    #[error("malformed proof: scalar `s` is not in `[0, n)`")]
    MalformedProofScalar,

    #[error("invalid public key: not a valid secp256k1 point")]
    InvalidPublicKey,

    #[error("verification failed: challenge mismatch")]
    VerificationFailed,

    #[error("hash-to-curve exhausted 256 counter values")]
    HashToCurveExhausted,

    #[error("scalar arithmetic produced zero (negligible probability under honest input)")]
    ScalarZero,

    #[error("rfc 6979 nonce generation exhausted 1024 hmac iterations")]
    Rfc6979Exhausted,

    #[error("secp256k1 backend error")]
    Backend(#[from] secp256k1::Error),
}

/// Errors raised by the `wrapper` module.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VonError {
    #[error("malformed proof")]
    MalformedProof,

    #[error("verification failed: proof does not bind to this public key / input")]
    WrongPublicKey,

    #[error("hmac-derived `r` exhausted 256 counter values (negligible probability)")]
    ScalarZero,

    #[error("schedule horizon {n} exceeds MAX_HORIZON ({max})")]
    HorizonTooLarge { n: u32, max: u32 },

    #[error("schedule horizon must be ≥ 1; got {n}")]
    HorizonZero { n: u32 },

    #[error("malformed schedule wire format: {0}")]
    MalformedSchedule(&'static str),

    #[error("ecvrf backend error")]
    Ecvrf(#[from] EcvrfError),
}
