//! Re-exports of `dark-confidential` primitives used by the SDK.
//!
//! Wallet integrators building confidential send, receive, scan, and
//! disclosure flows reach for this module so they can stay on the
//! single `dark-client` import surface. The shape mirrors the upstream
//! module layout in `dark-confidential` so a grep-and-jump from one
//! crate to the other lines up cleanly.
//!
//! # What lives here
//!
//! - **Stealth addressing** — [`MetaAddress`], [`ScanKey`], [`SpendKey`],
//!   [`StealthNetwork`], [`StealthSecrets`] for deriving the
//!   recipient-side identity from a seed and detecting inbound VTXOs.
//! - **Viewing keys** — [`ViewingKey`], [`ScopedViewingKey`],
//!   [`RoundWindow`] for selective audit-trail disclosure.
//! - **Commitments** — [`PedersenCommitment`] for amount-hiding outputs.
//! - **Range and balance proofs** — re-exported via the [`range_proof`]
//!   and [`balance_proof`] submodules so wallet code can construct
//!   [`range_proof::RangeProof`] / [`balance_proof::BalanceProof`]
//!   directly.
//! - **Disclosure proofs** — [`SelectiveReveal`], plus
//!   [`disclosure::bounded_range`] and [`disclosure::source_of_funds`]
//!   submodules for wallet-driven audit flows.
//!
//! See [`dark_confidential`] for the canonical documentation of each
//! primitive — this module is the SDK's pass-through, not a wrapper
//! layer.

pub use dark_confidential::commitment::{pedersen_h, PedersenCommitment};
pub use dark_confidential::stealth::{
    scan_announcement, scan_announcements, Announcement, MetaAddress, ScanKey, SpendKey,
    StealthNetwork, StealthSecrets,
};
pub use dark_confidential::viewing::{RoundWindow, ScopedViewingKey, ViewingKey};
pub use dark_confidential::{
    prove_selective_reveal, verify_selective_reveal, ConfidentialError, ConfidentialVtxo,
    DisclosedFields, SelectiveReveal,
};

pub mod balance_proof {
    //! Balance-proof re-exports — see [`dark_confidential::balance_proof`].
    pub use dark_confidential::balance_proof::{
        prove_balance, reconstruct_excess_point, verify_balance, BalanceProof,
    };
}

pub mod range_proof {
    //! Range-proof re-exports — see [`dark_confidential::range_proof`].
    pub use dark_confidential::range_proof::{
        prove_range, prove_range_aggregated, verify_range, verify_range_aggregated,
        verify_range_bounded, RangeProof, ValueCommitment, MAX_PROVABLE_AMOUNT,
    };
}

pub mod disclosure {
    //! Selective-disclosure proof re-exports.
    //!
    //! [`PedersenOpening`] is the cleartext input for bounded-range
    //! proofs; source-of-funds carries its own opening type because
    //! the on-the-wire format encodes the blinding scalar as hex (see
    //! [`source_of_funds::PedersenOpening`]).
    pub use dark_confidential::disclosure::{DisclosureError, PedersenOpening};

    pub mod bounded_range {
        //! Bounded-range disclosure proof.
        pub use dark_confidential::disclosure::bounded_range::{
            prove_bounded_range, verify_bounded_range, BoundedRangeProof,
        };
    }

    pub mod source_of_funds {
        //! Source-of-funds disclosure proof.
        pub use dark_confidential::disclosure::source_of_funds::{
            prove_source_of_funds, verify_source_of_funds, ChainRoot, DisclosureError, HopProof,
            PedersenOpening, SourceLink, SourceOfFundsProof, VtxoOutpoint,
        };
    }
}
