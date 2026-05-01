//! Verifiable Object Nonce (VON) primitives for PSAR.
//!
//! This crate hosts the cryptographic primitives that PSAR uses to commit
//! to a public schedule of MuSig2 nonces while keeping the underlying
//! scalars secret. Two layers:
//!
//! 1. [`ecvrf`] — an Elliptic Curve VRF over secp256k1, structurally
//!    compatible with RFC 9381 §5 but with a project-specific ciphersuite
//!    `DARK-VRF-SECP256K1-SHA256-TAI` (see `docs/adr/0006-ecvrf-dependency-strategy.md`).
//! 2. `wrapper` — VON.KeyGen / VON.Nonce / VON.Verify (issue #655, ADR-0007).
//!
//! Crate-level invariants:
//!
//! - `#![forbid(unsafe_code)]`.
//! - All public functions return `Result<_, EcvrfError>` or `Result<_, VonError>`
//!   per `docs/conventions/errors.md`.
//! - The only curve dependency is `secp256k1 = 0.29` (matches workspace pin).

#![forbid(unsafe_code)]

pub mod ecvrf;
pub mod error;
pub mod hash;
mod internal;
pub mod schedule;
pub mod wrapper;

pub use error::{EcvrfError, VonError};
