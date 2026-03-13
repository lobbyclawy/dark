//! Authentication middleware (macaroons)
//!
//! Implements macaroon-based authentication compatible with the original arkd.
//!
//! ## Token Format
//!
//! Tokens are base64-encoded macaroons with:
//! - Location: "arkd"
//! - Identifier: user's pubkey (hex-encoded x-only public key)
//! - First-party caveats for additional restrictions
//!
//! ## Security Notes
//!
//! - Root key should be randomly generated and stored securely
//! - Tokens should be transmitted over TLS only
//! - Consider adding expiry caveats for production use

use bitcoin::secp256k1::XOnlyPublicKey;
use macaroon::{Macaroon, MacaroonKey, Verifier};

use crate::{ApiError, ApiResult};

/// Macaroon location identifier
const MACAROON_LOCATION: &str = "arkd";
/// Caveat prefix for pubkey
const PUBKEY_CAVEAT_PREFIX: &str = "pubkey = ";

/// Macaroon-based authenticator
///
/// Compatible with original arkd authentication.
pub struct Authenticator {
    /// Root macaroon secret
    root_key: MacaroonKey,
}

impl Authenticator {
    /// Create a new authenticator with the given root key
    ///
    /// The root key should be at least 32 bytes of cryptographically random data.
    pub fn new(root_key: Vec<u8>) -> Self {
        Self {
            root_key: MacaroonKey::generate(&root_key),
        }
    }

    /// Create a new macaroon for a user with the given pubkey
    ///
    /// The pubkey should be a hex-encoded x-only (Schnorr) public key.
    pub fn create_macaroon(&self, pubkey: &XOnlyPublicKey) -> ApiResult<String> {
        let pubkey_hex = pubkey.to_string();

        // Create macaroon with pubkey as identifier
        let mut macaroon = Macaroon::create(
            Some(MACAROON_LOCATION.into()),
            &self.root_key,
            pubkey_hex.clone().into(),
        )
        .map_err(|e| ApiError::InternalError(format!("Failed to create macaroon: {e}")))?;

        // Add pubkey caveat for explicit verification
        // Note: add_first_party_caveat modifies in place, doesn't return Result
        macaroon.add_first_party_caveat(format!("{PUBKEY_CAVEAT_PREFIX}{pubkey_hex}").into());

        // Serialize to base64
        let serialized = macaroon
            .serialize(macaroon::Format::V2)
            .map_err(|e| ApiError::InternalError(format!("Failed to serialize macaroon: {e}")))?;

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serialized,
        ))
    }

    /// Verify a macaroon token and return whether it's valid
    pub fn verify_macaroon(&self, token: &str) -> ApiResult<bool> {
        self.verify_and_extract_pubkey(token)?;
        Ok(true)
    }

    /// Verify a macaroon token and extract the user's pubkey
    ///
    /// Returns the authenticated user's x-only public key.
    pub fn verify_and_extract_pubkey(&self, token: &str) -> ApiResult<XOnlyPublicKey> {
        // Decode from base64
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token)
            .map_err(|e| ApiError::AuthenticationError(format!("Invalid token encoding: {e}")))?;

        // Deserialize macaroon
        let macaroon = Macaroon::deserialize(&bytes)
            .map_err(|e| ApiError::AuthenticationError(format!("Invalid macaroon: {e}")))?;

        // Extract pubkey from identifier (need to own the data to avoid lifetime issues)
        let identifier_bytes = macaroon.identifier().0.clone();
        let pubkey_hex = std::str::from_utf8(&identifier_bytes)
            .map_err(|_| ApiError::AuthenticationError("Invalid identifier encoding".into()))?;

        // Parse pubkey
        let pubkey = parse_pubkey(pubkey_hex)?;

        // Build verifier with pubkey caveat check
        let mut verifier = Verifier::default();
        let expected_caveat = format!("{PUBKEY_CAVEAT_PREFIX}{pubkey_hex}");
        verifier.satisfy_exact(expected_caveat.into());

        // Verify macaroon
        verifier
            .verify(&macaroon, &self.root_key, vec![])
            .map_err(|e| ApiError::AuthenticationError(format!("Verification failed: {e}")))?;

        Ok(pubkey)
    }

    /// Extract user ID (pubkey hex) from a verified macaroon
    pub fn extract_user_id(&self, token: &str) -> ApiResult<String> {
        let pubkey = self.verify_and_extract_pubkey(token)?;
        Ok(pubkey.to_string())
    }
}

/// Parse a hex-encoded x-only public key
fn parse_pubkey(hex_str: &str) -> ApiResult<XOnlyPublicKey> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| ApiError::AuthenticationError(format!("Invalid pubkey hex: {e}")))?;

    XOnlyPublicKey::from_slice(&bytes)
        .map_err(|e| ApiError::AuthenticationError(format!("Invalid pubkey: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        secret.x_only_public_key(&secp).0
    }

    #[test]
    fn test_authenticator_creation() {
        let auth = Authenticator::new(vec![0u8; 32]);
        // Should not panic
        assert!(true);
        let _ = auth;
    }

    #[test]
    fn test_create_and_verify_macaroon() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        // Create macaroon
        let token = auth.create_macaroon(&pubkey).unwrap();
        assert!(!token.is_empty());

        // Verify and extract pubkey
        let extracted = auth.verify_and_extract_pubkey(&token).unwrap();
        assert_eq!(extracted, pubkey);
    }

    #[test]
    fn test_verify_macaroon_bool() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth.create_macaroon(&pubkey).unwrap();
        assert!(auth.verify_macaroon(&token).unwrap());
    }

    #[test]
    fn test_extract_user_id() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth.create_macaroon(&pubkey).unwrap();
        let user_id = auth.extract_user_id(&token).unwrap();
        assert_eq!(user_id, pubkey.to_string());
    }

    #[test]
    fn test_invalid_token() {
        let auth = Authenticator::new(vec![0u8; 32]);

        let result = auth.verify_and_extract_pubkey("not_valid_base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_root_key() {
        let auth1 = Authenticator::new(vec![0x01u8; 32]);
        let auth2 = Authenticator::new(vec![0x02u8; 32]);
        let pubkey = test_pubkey();

        // Create with auth1
        let token = auth1.create_macaroon(&pubkey).unwrap();

        // Verify with auth2 should fail
        let result = auth2.verify_and_extract_pubkey(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pubkey_valid() {
        let pubkey = test_pubkey();
        let hex = pubkey.to_string();
        let parsed = parse_pubkey(&hex).unwrap();
        assert_eq!(parsed, pubkey);
    }

    #[test]
    fn test_parse_pubkey_invalid_hex() {
        let result = parse_pubkey("not_hex_at_all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pubkey_wrong_length() {
        let result = parse_pubkey("abcd"); // Too short
        assert!(result.is_err());
    }
}
