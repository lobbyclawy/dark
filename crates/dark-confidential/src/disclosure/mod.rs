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
//! - [`source_of_funds`] — prove that a VTXO traces back to a stated
//!   source set of on-chain inputs or Ark round commitments via the
//!   linkable graph of confidential transactions, without revealing
//!   intermediate hops' amounts or recipients (#567).
//! - [`selective_reveal`] — opens a single VTXO's Pedersen commitment
//!   plus optional metadata fields, bound to the VTXO's outpoint and
//!   owner pubkey via a tagged-hash transcript (#565).
//!
//! # Commitment convention
//!
//! Bounded-range disclosure rides on [`crate::range_proof`]'s
//! [`ValueCommitment`] (`amount · H + blinding · G` per ADR-0001), not
//! on [`crate::commitment::PedersenCommitment`]. The two types are not
//! byte-compatible; callers building a bounded-range disclosure must
//! commit through `range_proof::ValueCommitment::commit` to get a
//! commitment the disclosure proof can bind to. Selective reveal binds
//! to the standard [`crate::commitment::PedersenCommitment`].
//!
//! # Privacy boundary
//!
//! Each disclosure type opens *only* the data the wallet places in it.
//! In particular, none of [`bounded_range`], [`selective_reveal`], or
//! [`source_of_funds`] discloses:
//! - other VTXOs the wallet owns,
//! - the round / round-tree graph the disclosed VTXO belongs to,
//! - any nullifier, scan key, or stealth metadata,
//! - any commitment chain ancestors or descendants beyond what the
//!   source-of-funds proof's [`HopProof`] chain explicitly opens.
//!
//! Source-of-funds disclosure carries its own `DisclosureError` flavor
//! (re-exported as [`source_of_funds::DisclosureError`]) so its
//! hop-graph specific failure modes do not get conflated with the
//! bounded-range / selective-reveal error surface.
//!
//! [`ValueCommitment`]: crate::range_proof::ValueCommitment

use secp256k1::Scalar;

use crate::ConfidentialError;

pub mod bounded_range;
pub mod selective_reveal;
pub mod source_of_funds;

pub use bounded_range::{
    prove_bounded_range, verify_bounded_range, BoundedRangeProof, BOUNDED_RANGE_TRANSCRIPT_DST,
};
pub use selective_reveal::{
    prove_selective_reveal, verify_selective_reveal, DisclosedFields, SelectiveReveal,
    SELECTIVE_REVEAL_DST,
};
pub use source_of_funds::{
    prove_source_of_funds, verify_source_of_funds, ChainRoot, HopProof, SourceLink,
    SourceOfFundsProof, VtxoOutpoint, SOURCE_OF_FUNDS_DST,
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

    /// Commit to this opening, producing the corresponding
    /// [`crate::commitment::PedersenCommitment`].
    pub fn commit(&self) -> crate::Result<crate::commitment::PedersenCommitment> {
        crate::commitment::PedersenCommitment::commit(self.amount, &self.blinding)
    }

    /// Explicit copy alias. Equivalent to `Clone::clone`; named to make
    /// secret-material duplication call sites greppable.
    pub fn cloned(&self) -> Self {
        self.clone()
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
