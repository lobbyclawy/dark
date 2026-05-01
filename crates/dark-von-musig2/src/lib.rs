//! VON-augmented MuSig2 (BIP-327) for PSAR.
//!
//! See `docs/adr/0008-musig2-nonce-injection.md` for the dependency
//! decision: BIP-327 is implemented in the private [`bip327`] module
//! on top of `secp256k1 = 0.29`; the public adapter
//! [`sign::sign_partial_with_von`] consumes `(r₁, r₂)` scalars from
//! [`dark_von::wrapper::nonce`] (#655) directly — no internal hashing
//! step washes out the VON binding.
//!
//! Cross-validation against the upstream `musig2 = "0.3.1"` crate
//! lives under `tests/`.
//!
//! Crate-level invariants:
//!
//! - `#![forbid(unsafe_code)]`.
//! - All public functions return `Result<_, VonMusig2Error>` per
//!   `docs/conventions/errors.md`.
//! - Only curve dep: `secp256k1 = 0.29`.

#![forbid(unsafe_code)]

mod bip327;
pub mod epoch;
pub mod error;
pub mod nonces;
pub mod presign;
pub mod setup;
pub mod sign;

pub use error::{Bip327Error, VonMusig2Error};
pub use nonces::{AggNonce, PubNonce};
pub use sign::{sign_partial_with_von, PartialSignature};
