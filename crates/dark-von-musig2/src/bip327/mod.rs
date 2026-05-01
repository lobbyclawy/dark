//! Private BIP-327 (MuSig2) routines.
//!
//! Per ADR-0008, this module is intentionally minimal: only the routines
//! the VON adapter ([`crate::sign::sign_partial_with_von`]) needs to
//! produce a partial signature wire-compatible with `musig2 = "0.3.1"`.
//!
//! Surface (all `pub(crate)`):
//! - [`key_agg::key_agg`] — KeyAgg per BIP-327
//! - [`sign::partial_sign_with_scalars`] — partial signing with
//!   externally-supplied `(k₁, k₂)` scalars
//! - [`sign::aggregate_and_finalize`] — sum partial sigs, build BIP-340
//!   `(R_x, s)`
//! - [`sign::session_values`] — per-session `(b, R, e)`
//!
//! Cross-validated against `musig2 = "0.3.1"` via dev-dep tests under
//! `tests/`.

pub(crate) mod internal;
pub(crate) mod key_agg;
pub(crate) mod sign;
mod tagged;
