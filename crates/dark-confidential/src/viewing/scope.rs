//! Scope binding for viewing keys.
//!
//! A *scope* encodes the audit window a viewing key is allowed to cover.
//! The viewing-scope ADR (issue #561) is still being decided. Until it
//! lands, this module encodes the scope as an inclusive
//! `[start_round, end_round]` round window.
//!
//! # Scope tweak
//!
//! The scoped secret is computed from the master viewing key by adding
//! a deterministic, scope-bound tweak to the scalar:
//!
//! ```text
//!   tweak     = HMAC-SHA512(key = master_secret_bytes,
//!                           msg = SCOPE_DST || start_be8 || end_be8)[..32]
//!   k_scoped  = (k_master + tweak) mod n
//! ```
//!
//! Because the tweak is keyed by the master secret, knowing a scoped
//! key does not let the holder recover the master — inverting the tweak
//! requires the master itself.
//!
//! TODO(#561): swap [`RoundWindow`] for the final ADR shape (epoch,
//! time, or whatever else lands) without changing the public API of
//! [`crate::viewing`]. The wire encoding is intentionally local to this
//! file so that migration is one-file deep.

use hmac::{Hmac, Mac};
use secp256k1::{Scalar, SecretKey};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{ConfidentialError, Result};

/// Domain-separation tag for the viewing-scope tweak. Versioned so a
/// future scope encoding can mint `v2` without colliding with v1.
pub const SCOPE_DST: &[u8] = b"dark-confidential viewing scope v1";

type HmacSha512 = Hmac<Sha512>;

/// Inclusive round-window bounds for a [`crate::viewing::ScopedViewingKey`].
///
/// TODO(#561): the final viewing-scope ADR may migrate this to epoch- or
/// time-based bounds. The wire encoding lives behind this type so that
/// migration is a single-file change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoundWindow {
    pub start_round: u64,
    pub end_round: u64,
}

impl RoundWindow {
    /// Build an inclusive round window. Returns
    /// [`ConfidentialError::Viewing`] if `start_round > end_round`.
    pub fn new(start_round: u64, end_round: u64) -> Result<Self> {
        if start_round > end_round {
            return Err(ConfidentialError::Viewing(
                "scope: start_round must be <= end_round",
            ));
        }
        Ok(Self {
            start_round,
            end_round,
        })
    }

    /// Constant-time membership test for `round`.
    ///
    /// Runs in time independent of `round`, `start_round`, and
    /// `end_round`: both sub-comparisons always execute, the
    /// less-than-or-equal check is reduced to a sign-bit extraction on
    /// a 128-bit subtraction, and there is no `if`/`match` on the
    /// secret-derived intermediate.
    pub fn contains_ct(&self, round: u64) -> bool {
        let in_lower = ge_u64_ct(round, self.start_round);
        let in_upper = ge_u64_ct(self.end_round, round);
        (in_lower & in_upper) == 1
    }
}

/// Compute `SK_scoped = SK + HMAC-SHA512(SK, SCOPE_DST || start || end)[..32]`
/// modulo the curve order.
pub(crate) fn derive_scoped_secret(master: &SecretKey, scope: RoundWindow) -> Result<SecretKey> {
    let master_bytes = Zeroizing::new(master.secret_bytes());
    let mut mac = HmacSha512::new_from_slice(master_bytes.as_ref())
        .expect("HMAC-SHA512 accepts keys of any length");
    mac.update(SCOPE_DST);
    mac.update(&scope.start_round.to_be_bytes());
    mac.update(&scope.end_round.to_be_bytes());
    let tag: Zeroizing<[u8; 64]> = Zeroizing::new(mac.finalize().into_bytes().into());

    let mut tweak_bytes = Zeroizing::new([0u8; 32]);
    tweak_bytes.copy_from_slice(&tag[..32]);

    let tweak = Scalar::from_be_bytes(*tweak_bytes)
        .map_err(|_| ConfidentialError::Viewing("scope tweak exceeds curve order"))?;
    master
        .add_tweak(&tweak)
        .map_err(|_| ConfidentialError::Viewing("scope tweak resulted in zero key"))
}

/// Constant-time `a >= b` for `u64`, returning `0` or `1`.
///
/// Uses the standard "borrow flag is sign bit" trick on a 128-bit
/// subtraction, so the result is independent of the operand bits.
#[inline(always)]
fn ge_u64_ct(a: u64, b: u64) -> u64 {
    let diff = (a as u128).wrapping_sub(b as u128);
    1 - ((diff >> 127) as u64 & 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inverted_bounds() {
        let err = RoundWindow::new(10, 5).unwrap_err();
        assert!(matches!(err, ConfidentialError::Viewing(_)));
    }

    #[test]
    fn singleton_window_is_valid() {
        let w = RoundWindow::new(42, 42).expect("singleton");
        assert!(w.contains_ct(42));
        assert!(!w.contains_ct(41));
        assert!(!w.contains_ct(43));
    }

    #[test]
    fn membership_at_inclusive_bounds_and_outside() {
        let w = RoundWindow::new(100, 200).expect("scope");
        assert!(w.contains_ct(100));
        assert!(w.contains_ct(150));
        assert!(w.contains_ct(200));
        assert!(!w.contains_ct(99));
        assert!(!w.contains_ct(201));
        assert!(!w.contains_ct(0));
        assert!(!w.contains_ct(u64::MAX));
    }

    #[test]
    fn ge_u64_ct_matches_native_compare() {
        for (a, b) in &[
            (0u64, 0u64),
            (0, 1),
            (1, 0),
            (u64::MAX, u64::MAX),
            (u64::MAX, 0),
            (0, u64::MAX),
            (123, 124),
            (124, 123),
            (1 << 63, (1 << 63) - 1),
        ] {
            let expected = u64::from(a >= b);
            assert_eq!(ge_u64_ct(*a, *b), expected, "ge_u64_ct({a}, {b})");
        }
    }
}
