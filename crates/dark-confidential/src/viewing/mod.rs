//! Viewing key derivation and scoped access for selective disclosure
//! (issue #564).
//!
//! A *viewing key* grants read-only ability to detect and decrypt the
//! holder's VTXOs and announcements. It MUST NOT grant the ability to
//! spend. Issue #564 splits the construction into two layers:
//!
//! 1. A master viewing key derived from the wallet seed, sitting in the
//!    same BIP-32 tree as the stealth scan and spend keys (see
//!    [`crate::stealth::derivation::view_path`]). Determinism is
//!    required so a wallet can recover or reissue the viewing key from
//!    its seed alone.
//!
//! 2. A *scoped* viewing key that additionally binds the master to a
//!    window of rounds via the scope tweak in [`scope`]. The scope
//!    mechanism is the subject of ADR #561 — until that ADR lands the
//!    scope is encoded as an inclusive `[start_round, end_round]` round
//!    window. Migration to the final scope shape is tracked at the
//!    `TODO(#561)` markers in this module.
//!
//! # Threat model
//!
//! - The viewing secret is high-value: leaking it leaks every in-scope
//!   transaction. [`ViewingKey`] and [`ScopedViewingKey`] intentionally
//!   implement neither `Clone`, nor `Copy`, nor `Debug`, nor `Display`,
//!   nor `Serialize`. Bytes leave only via the explicit
//!   `expose_secret()` accessors so an `expose_secret` grep finds every
//!   disclosure site.
//! - Both wrappers `Zeroize` their inner [`secp256k1::SecretKey`] on
//!   drop via `non_secure_erase`, matching the policy used by
//!   [`crate::stealth::keys`].
//! - The scope-window check is constant-time over the bounds so an
//!   attacker observing decrypt-attempt timings cannot learn the window
//!   shape.

pub mod keys;
pub mod scope;

pub use keys::{ScopedViewingKey, ViewingKey};
pub use scope::{RoundWindow, SCOPE_DST};
