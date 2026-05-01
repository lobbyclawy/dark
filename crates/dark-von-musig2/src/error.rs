//! Crate error types.

use thiserror::Error;

/// Errors raised by the private `bip327` module.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Bip327Error {
    #[error("zero or empty pubkey set")]
    EmptyPubkeySet,

    #[error("aggregated public key is the point at infinity")]
    InfiniteAggregateKey,

    #[error("nonce contribution scalar is zero")]
    ZeroNonceScalar,

    #[error("malformed pubnonce wire bytes (expected 66 B compressed `R₁ || R₂`)")]
    MalformedPubNonce,

    #[error("malformed aggnonce wire bytes (expected 66 B)")]
    MalformedAggNonce,

    #[error("malformed partial signature (expected 32 B scalar)")]
    MalformedPartialSignature,

    #[error("partial signature scalar is not in `[0, n)`")]
    PartialSignatureOutOfRange,

    #[error("partial signature aggregation produced infinity (degenerate)")]
    AggregateInfinity,

    #[error("partial signature does not satisfy bip-327 partial-sig verify equation")]
    InvalidPartialSignature,

    #[error("scalar arithmetic produced zero (negligible probability under honest input)")]
    ScalarZero,

    #[error("secp256k1 backend error")]
    Backend(#[from] secp256k1::Error),
}

/// Errors raised by the public `sign` / `nonces` surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VonMusig2Error {
    #[error("bip-327 backend error")]
    Bip327(#[from] Bip327Error),

    #[error("operator public key is not in the key-agg set")]
    OperatorNotInKeyAgg,

    #[error("invalid secp256k1 point in the von nonce")]
    InvalidVonPoint,

    #[error("dark-von error")]
    DarkVon(#[from] dark_von::VonError),

    #[error("malformed published schedule wire bytes: {0}")]
    MalformedPublishedSchedule(&'static str),

    #[error("epoch index t={t} out of range; max horizon is {max}")]
    EpochOutOfRange { t: u32, max: u32 },

    #[error("participant partial signature failed bip-327 partial-sig verify")]
    InvalidParticipantPartialSig,

    #[error("cbor decoding failed: {0}")]
    Cbor(String),
}
