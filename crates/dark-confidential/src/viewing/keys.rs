//! Private-key wrappers for viewing keys (issue #564).
//!
//! Mirrors the `Zeroize` / no-`Copy` / no-`Clone` / no-`Debug` policy
//! used by [`crate::stealth::keys`]: viewing-key bytes must never be
//! silently duplicated or logged.
//!
//! Two wrapper types live here:
//!
//! - [`ViewingKey`] — the master, account-level viewing secret. Derived
//!   from the wallet seed via [`ViewingKey::from_seed`].
//! - [`ScopedViewingKey`] — a viewing secret that has been bound to an
//!   inclusive round window via the scope-tweak in
//!   [`crate::viewing::scope`]. Decryption is gated by
//!   [`ScopedViewingKey::may_view`], whose timing is independent of the
//!   scope bounds.
//!
//! Both types `Zeroize` their inner [`secp256k1::SecretKey`] on drop via
//! `non_secure_erase`. Bytes leave a wrapper only via the
//! `expose_secret()` accessor, which is the audit anchor — a code search
//! for that name finds every disclosure site.

use bitcoin::bip32::Xpriv;
use bitcoin::NetworkKind;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::stealth::derivation::view_path;
use crate::viewing::scope::{derive_scoped_secret, RoundWindow};
use crate::{ConfidentialError, Result};

/// Master, account-level viewing secret.
///
/// Derived from a BIP-32 master via the path documented in
/// [`crate::stealth::derivation::view_path`]. A holder of this key can
/// decrypt all of the wallet's VTXOs and announcements; treat it with
/// the same care as the spend key when transmitting.
///
/// The lack of a `Debug` impl is a load-bearing invariant. The doctest
/// below asserts it at compile time:
///
/// ```compile_fail
/// use dark_confidential::viewing::ViewingKey;
/// fn must_be_debug<T: std::fmt::Debug>(_: &T) {}
/// let k = ViewingKey::from_seed(&[0u8; 32], 0).unwrap();
/// must_be_debug(&k);
/// ```
pub struct ViewingKey(SecretKey);

/// Viewing secret bound to a specific round window.
///
/// Construct via [`ViewingKey::scope_to`]. Verifier code MUST gate
/// decryption attempts on [`ScopedViewingKey::may_view`] before
/// consulting [`ScopedViewingKey::expose_secret`]. The check is
/// constant-time over the round bounds.
///
/// Like [`ViewingKey`], this type is intentionally not `Debug`:
///
/// ```compile_fail
/// use dark_confidential::viewing::{RoundWindow, ViewingKey};
/// fn must_be_debug<T: std::fmt::Debug>(_: &T) {}
/// let k = ViewingKey::from_seed(&[0u8; 32], 0).unwrap();
/// let s = k.scope_to(RoundWindow::new(0, 1).unwrap()).unwrap();
/// must_be_debug(&s);
/// ```
pub struct ScopedViewingKey {
    secret: SecretKey,
    scope: RoundWindow,
}

impl ViewingKey {
    /// Wraps a raw [`SecretKey`] without copying its bytes. Pub-crate so
    /// callers cannot fabricate a `ViewingKey` outside of the canonical
    /// derivation.
    pub(crate) fn new(secret: SecretKey) -> Self {
        Self(secret)
    }

    /// Deterministically derives the viewing key for `account_index`
    /// from a wallet `seed`.
    ///
    /// The derivation path is documented in
    /// [`crate::stealth::derivation::view_path`]; it sits adjacent to
    /// the scan and spend paths so all three keys share the same
    /// account-level prefix.
    pub fn from_seed(seed: &[u8], account_index: u32) -> Result<Self> {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Main, seed)
            .map_err(|_| ConfidentialError::Viewing("invalid wallet seed for BIP-32 master"))?;
        let xpriv = master
            .derive_priv(&secp, &view_path(account_index))
            .map_err(|_| ConfidentialError::Viewing("viewing key derivation failed"))?;
        Ok(Self::new(xpriv.private_key))
    }

    /// Bind this viewing key to a round window, producing a
    /// [`ScopedViewingKey`] suitable for handing to an audit consumer.
    pub fn scope_to(&self, scope: RoundWindow) -> Result<ScopedViewingKey> {
        let secret = derive_scoped_secret(&self.0, scope)?;
        Ok(ScopedViewingKey { secret, scope })
    }

    /// Returns the public key associated with this viewing secret.
    /// Useful when publishing a viewing-key receipt that downstream code
    /// can match against without holding the secret itself.
    pub fn pubkey(&self) -> PublicKey {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.0)
    }

    /// Borrow the underlying [`SecretKey`]. Audit-anchor accessor —
    /// every disclosure site is reachable by `grep expose_secret`.
    pub fn expose_secret(&self) -> &SecretKey {
        &self.0
    }
}

impl ScopedViewingKey {
    /// The round window this key is bound to.
    pub fn scope(&self) -> RoundWindow {
        self.scope
    }

    /// Borrow the scoped [`SecretKey`]. Same audit-anchor convention as
    /// [`ViewingKey::expose_secret`].
    pub fn expose_secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Constant-time gate on decryption: returns `true` iff `round`
    /// falls inside [`Self::scope`]. Verifier code MUST consult this
    /// before attempting to decrypt a VTXO/announcement.
    pub fn may_view(&self, round: u64) -> bool {
        self.scope.contains_ct(round)
    }
}

impl Zeroize for ViewingKey {
    fn zeroize(&mut self) {
        self.0.non_secure_erase();
    }
}

impl Drop for ViewingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ViewingKey {}

impl Zeroize for ScopedViewingKey {
    fn zeroize(&mut self) {
        self.secret.non_secure_erase();
    }
}

impl Drop for ScopedViewingKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ScopedViewingKey {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    fn key(seed: &[u8], account: u32) -> ViewingKey {
        ViewingKey::from_seed(seed, account).expect("derive viewing key")
    }

    #[test]
    fn from_seed_is_deterministic() {
        let a = key(&sample_seed(), 0);
        let b = key(&sample_seed(), 0);
        assert_eq!(
            a.expose_secret().secret_bytes(),
            b.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn distinct_accounts_yield_distinct_keys() {
        let a = key(&sample_seed(), 0);
        let b = key(&sample_seed(), 1);
        assert_ne!(
            a.expose_secret().secret_bytes(),
            b.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn distinct_seeds_yield_distinct_keys() {
        let a = key(&sample_seed(), 0);
        let mut other = sample_seed();
        other[0] ^= 0xff;
        let b = key(&other, 0);
        assert_ne!(
            a.expose_secret().secret_bytes(),
            b.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn viewing_pubkey_differs_from_scan_and_spend_at_same_account() {
        // Ensures the new VIEW_BRANCH does not collide with SCAN_BRANCH
        // or SPEND_BRANCH at the BIP-32 layer. Distinct private secrets
        // produce distinct public keys with overwhelming probability,
        // so the public-key witness is sufficient and avoids exposing
        // the scan/spend secret bytes through a test accessor.
        use crate::stealth::{MetaAddress, StealthNetwork};

        let view = key(&sample_seed(), 0);
        let (_, secrets) =
            MetaAddress::from_seed(&sample_seed(), 0, StealthNetwork::Mainnet).unwrap();
        assert_ne!(view.pubkey(), secrets.scan_key.pubkey());
        assert_ne!(view.pubkey(), secrets.spend_key.pubkey());
    }

    #[test]
    fn scoped_key_decrypts_only_within_window() {
        let k = key(&sample_seed(), 0);
        let scope = RoundWindow::new(100, 200).expect("scope");
        let scoped = k.scope_to(scope).expect("scope_to");

        assert!(scoped.may_view(100), "lower bound is inclusive");
        assert!(scoped.may_view(150), "midpoint allowed");
        assert!(scoped.may_view(200), "upper bound is inclusive");
        assert!(!scoped.may_view(99), "below lower bound rejected");
        assert!(!scoped.may_view(201), "above upper bound rejected");
        assert!(!scoped.may_view(0), "far-below rejected");
        assert!(!scoped.may_view(u64::MAX), "far-above rejected");
    }

    #[test]
    fn scope_round_trips_back_through_scope_accessor() {
        let k = key(&sample_seed(), 0);
        let scope = RoundWindow::new(7, 42).unwrap();
        let scoped = k.scope_to(scope).unwrap();
        assert_eq!(scoped.scope(), scope);
    }

    #[test]
    fn scoped_keys_for_distinct_windows_differ() {
        let k = key(&sample_seed(), 0);
        let a = k.scope_to(RoundWindow::new(100, 200).unwrap()).unwrap();
        let b = k.scope_to(RoundWindow::new(101, 200).unwrap()).unwrap();
        assert_ne!(
            a.expose_secret().secret_bytes(),
            b.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn scoped_key_differs_from_master() {
        let k = key(&sample_seed(), 0);
        let scoped = k.scope_to(RoundWindow::new(100, 200).unwrap()).unwrap();
        assert_ne!(
            k.expose_secret().secret_bytes(),
            scoped.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn scoped_keys_for_distinct_master_keys_differ_under_same_scope() {
        let scope = RoundWindow::new(100, 200).unwrap();
        let a = key(&sample_seed(), 0).scope_to(scope).unwrap();
        let b = key(&sample_seed(), 1).scope_to(scope).unwrap();
        assert_ne!(
            a.expose_secret().secret_bytes(),
            b.expose_secret().secret_bytes()
        );
    }

    #[test]
    fn pubkey_is_deterministic() {
        let a = key(&sample_seed(), 0);
        let b = key(&sample_seed(), 0);
        assert_eq!(a.pubkey(), b.pubkey());
    }
}
