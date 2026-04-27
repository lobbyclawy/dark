//! Selective-disclosure primitives for Confidential VTXOs.
//!
//! This module hosts the wallet-facing proofs that a holder can ship to
//! an auditor or counterparty without revealing the underlying value.
//! Each submodule covers one disclosure shape; they share the
//! [`PedersenOpening`] input type and the [`DisclosureError`] surface so
//! callers can treat the family uniformly.
//!
//! # Disclosure shapes
//!
//! - [`bounded_range`] — proves the cleartext amount lies in a
//!   sender-specified `[lower, upper]` interval (#566).
//!
//! Future submodules (#565 selective reveal, #567 source-of-funds) plug
//! into the same scaffolding.
//!
//! # Commitment convention
//!
//! Bounded-range disclosure rides on [`crate::range_proof`]'s
//! [`ValueCommitment`] (`amount · H + blinding · G` per ADR-0001), not
//! on [`crate::commitment::PedersenCommitment`]. The two types are not
//! byte-compatible; callers building a disclosure must commit through
//! `range_proof::ValueCommitment::commit` to get a commitment the
//! disclosure proof can bind to.
//!
//! [`ValueCommitment`]: crate::range_proof::ValueCommitment

use secp256k1::Scalar;

use crate::ConfidentialError;

pub mod bounded_range;

pub use bounded_range::{
    prove_bounded_range, verify_bounded_range, BoundedRangeProof, BOUNDED_RANGE_TRANSCRIPT_DST,
};

/// Cleartext opening for a Pedersen commitment.
///
/// Holds the `amount` and `blinding` scalar that, together, reconstruct
/// the public commitment under the range-proof convention. Callers
/// supply this to disclosure prove paths; verifiers never see it.
#[derive(Debug, Clone)]
pub struct PedersenOpening {
    pub amount: u64,
    pub blinding: Scalar,
}

impl PedersenOpening {
    pub fn new(amount: u64, blinding: Scalar) -> Self {
        Self { amount, blinding }
    }
}

/// Error surface for selective-disclosure proofs.
///
/// Distinct from [`crate::ConfidentialError`] so callers can match on
/// disclosure-specific failure modes without conflating them with the
/// underlying primitive errors. Each variant carries the originating
/// [`ConfidentialError`] when one was produced.
#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error("invalid bounds: {0}")]
    InvalidBounds(&'static str),
    #[error("opening does not match the commitment")]
    OpeningMismatch,
    #[error("amount {amount} is outside the asserted range [{lower}, {upper}]")]
    AmountOutOfRange { amount: u64, lower: u64, upper: u64 },
    #[error("verified range [{verified_min}, {verified_max}] does not certify the asserted range [{lower}, {upper}]")]
    RangeNotCertified {
        lower: u64,
        upper: u64,
        verified_min: u64,
        verified_max: u64,
    },
    #[error("transcript binding mismatch")]
    TranscriptMismatch,
    #[error("invalid encoding: {0}")]
    InvalidEncoding(&'static str),
    #[error(transparent)]
    Underlying(#[from] ConfidentialError),
}
