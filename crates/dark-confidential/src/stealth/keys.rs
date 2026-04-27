//! Private-key wrappers for stealth scan and spend keys.
//!
//! Both types intentionally:
//! - do not implement `Copy` or `Clone` — the private key bytes must
//!   never be silently duplicated. If a caller really needs a clone,
//!   they must derive again from the seed.
//! - do not implement `Debug` or `Display` — the [`Debug`] format of
//!   [`secp256k1::SecretKey`] hides the bytes, but it still leaks
//!   *which* secret was used. Forcing the absence of a formatter means
//!   accidental `tracing::debug!("{:?}", scan_key)` calls fail at compile
//!   time rather than at audit time.
//! - zeroize their inner `SecretKey` on drop via `Zeroize` so the bytes
//!   do not linger on the stack/heap after the wrapper goes out of scope.
//! - expose `pubkey()` so callers can derive the public-facing component
//!   without ever touching the secret directly.

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret key authorising **detection** of incoming VTXOs.
///
/// A scan key may be shared with a watch-only service to detect inbound
/// payments without granting spend authority. See module docs for the
/// `Copy`/`Clone`/`Debug` policy.
pub struct ScanKey(SecretKey);

impl ScanKey {
    /// Borrow the underlying secret for scanning operations.
    ///
    /// Required by ECDH-based recipient scanning (issue #555) and by the
    /// `dark-client` stealth scanner (#558) which detects inbound VTXOs
    /// from public round announcements. Callers MUST treat the returned
    /// reference as transient and MUST NOT log, clone, or otherwise
    /// duplicate the bytes — the `ScanKey` wrapper still owns the
    /// material and will zeroize it on drop.
    pub fn as_secret(&self) -> &SecretKey {
        &self.0
    }
}

/// Secret key authorising **spending** of received VTXOs.
///
/// The spend key MUST never leave the wallet. See module docs for the
/// `Copy`/`Clone`/`Debug` policy.
pub struct SpendKey(SecretKey);

macro_rules! impl_secret_key_wrapper {
    ($wrapper:ident) => {
        impl $wrapper {
            /// Wraps a [`SecretKey`] without copying its bytes.
            pub(crate) fn new(secret: SecretKey) -> Self {
                Self(secret)
            }

            /// Returns the public key associated with this secret key.
            pub fn pubkey(&self) -> PublicKey {
                PublicKey::from_secret_key(&Secp256k1::new(), &self.0)
            }
        }

        impl Zeroize for $wrapper {
            fn zeroize(&mut self) {
                self.0.non_secure_erase();
            }
        }

        impl Drop for $wrapper {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl ZeroizeOnDrop for $wrapper {}
    };
}

impl_secret_key_wrapper!(ScanKey);
impl_secret_key_wrapper!(SpendKey);

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_secret() -> SecretKey {
        SecretKey::from_slice(&[1u8; 32]).expect("non-zero is valid")
    }

    #[test]
    fn pubkey_is_deterministic() {
        let scan = ScanKey::new(dummy_secret());
        assert_eq!(scan.pubkey(), scan.pubkey());
    }

    #[test]
    fn scan_and_spend_pubkey_independent_per_secret() {
        let scan = ScanKey::new(dummy_secret());
        let spend = SpendKey::new(SecretKey::from_slice(&[2u8; 32]).unwrap());
        assert_ne!(scan.pubkey(), spend.pubkey());
    }

    #[test]
    fn scan_key_as_secret_borrows_the_underlying_secret_key() {
        let secret = dummy_secret();
        let scan = ScanKey::new(secret);
        // The pubkey derived from `as_secret` must agree with the
        // wrapper's own `pubkey` accessor — the borrowed reference is
        // the same scalar.
        let secp = Secp256k1::new();
        assert_eq!(
            PublicKey::from_secret_key(&secp, scan.as_secret()),
            scan.pubkey(),
        );
    }
}
