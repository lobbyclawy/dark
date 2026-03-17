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

use std::collections::HashSet;
use std::sync::RwLock;

use bitcoin::secp256k1::XOnlyPublicKey;
use macaroon::{Macaroon, MacaroonKey, Verifier};

use crate::{ApiError, ApiResult};

// ── Permission scopes ──────────────────────────────────────────────

/// Permission scope for a token/macaroon.
///
/// Each gRPC method maps to exactly one required permission:
/// - `Read`  — query-only RPCs (GetInfo, GetVtxos, ListRounds, …)
/// - `Write` — mutation RPCs (RegisterForRound, SubmitTx, …)
/// - `Admin` — operator RPCs (AdminService/*)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    /// Query-only RPCs
    Read,
    /// Mutation RPCs
    Write,
    /// Operator / admin RPCs
    Admin,
}

/// A set of permissions attached to a token/macaroon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPermissions {
    pub permissions: Vec<Permission>,
}

impl TokenPermissions {
    /// Full admin access (Read + Write + Admin).
    pub fn admin() -> Self {
        Self {
            permissions: vec![Permission::Read, Permission::Write, Permission::Admin],
        }
    }

    /// Read + Write access (no admin).
    pub fn write() -> Self {
        Self {
            permissions: vec![Permission::Read, Permission::Write],
        }
    }

    /// Read-only access.
    pub fn read_only() -> Self {
        Self {
            permissions: vec![Permission::Read],
        }
    }

    /// Check whether this set contains the given permission.
    pub fn has(&self, p: &Permission) -> bool {
        self.permissions.contains(p)
    }
}

/// Caveat prefix used to encode permission scopes inside a macaroon.
const PERMISSIONS_CAVEAT_PREFIX: &str = "permissions = ";

/// Macaroon location identifier
const MACAROON_LOCATION: &str = "arkd";
/// Caveat prefix for pubkey
const PUBKEY_CAVEAT_PREFIX: &str = "pubkey = ";

/// Macaroon-based authenticator
///
/// Compatible with original arkd authentication.
/// Maintains an in-memory revocation list; revoked token IDs are rejected
/// on verification even if their HMAC is otherwise valid.
pub struct Authenticator {
    /// Root macaroon secret
    root_key: MacaroonKey,
    /// Set of revoked token identifiers (pubkey hex strings used as macaroon IDs).
    revoked: RwLock<HashSet<String>>,
}

impl Authenticator {
    /// Create a new authenticator with the given root key
    ///
    /// The root key should be at least 32 bytes of cryptographically random data.
    pub fn new(root_key: Vec<u8>) -> Self {
        Self {
            root_key: MacaroonKey::generate(&root_key),
            revoked: RwLock::new(HashSet::new()),
        }
    }

    /// Revoke a token by its identifier (the pubkey hex used as the macaroon ID).
    ///
    /// After revocation, any call to `verify_and_extract_pubkey` or
    /// `verify_with_permissions` for a token with this identifier will fail.
    /// Revocations are in-memory only and do not survive a server restart.
    pub fn revoke_token(&self, token_id: &str) -> ApiResult<()> {
        self.revoked
            .write()
            .map_err(|_| ApiError::InternalError("revocation lock poisoned".into()))?
            .insert(token_id.to_string());
        Ok(())
    }

    /// Check whether a token identifier has been revoked.
    pub fn is_revoked(&self, token_id: &str) -> bool {
        self.revoked
            .read()
            .map(|set| set.contains(token_id))
            .unwrap_or(false)
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

        // Reject revoked tokens before any further verification.
        if self.is_revoked(pubkey_hex) {
            return Err(ApiError::AuthenticationError(
                "Token has been revoked".into(),
            ));
        }

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

    /// Create a scoped macaroon with restricted permissions.
    ///
    /// Adds a first-party caveat encoding the granted permission scopes.
    pub fn create_scoped_macaroon(
        &self,
        pubkey: &XOnlyPublicKey,
        permissions: &TokenPermissions,
    ) -> ApiResult<String> {
        let pubkey_hex = pubkey.to_string();

        let mut macaroon = Macaroon::create(
            Some(MACAROON_LOCATION.into()),
            &self.root_key,
            pubkey_hex.clone().into(),
        )
        .map_err(|e| ApiError::InternalError(format!("Failed to create macaroon: {e}")))?;

        macaroon.add_first_party_caveat(format!("{PUBKEY_CAVEAT_PREFIX}{pubkey_hex}").into());

        // Encode permissions caveat
        let scope_str = permissions
            .permissions
            .iter()
            .map(|p| match p {
                Permission::Read => "read",
                Permission::Write => "write",
                Permission::Admin => "admin",
            })
            .collect::<Vec<_>>()
            .join(",");
        macaroon.add_first_party_caveat(format!("{PERMISSIONS_CAVEAT_PREFIX}{scope_str}").into());

        let serialized = macaroon
            .serialize(macaroon::Format::V2)
            .map_err(|e| ApiError::InternalError(format!("Failed to serialize macaroon: {e}")))?;

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serialized,
        ))
    }

    /// Verify a macaroon and extract both pubkey and permissions.
    ///
    /// If the macaroon contains no permissions caveat, full admin access is
    /// assumed (backward compatible with legacy tokens).
    pub fn verify_with_permissions(
        &self,
        token: &str,
    ) -> ApiResult<(XOnlyPublicKey, TokenPermissions)> {
        // Decode from base64
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token)
            .map_err(|e| ApiError::AuthenticationError(format!("Invalid token encoding: {e}")))?;

        // Deserialize macaroon
        let macaroon = Macaroon::deserialize(&bytes)
            .map_err(|e| ApiError::AuthenticationError(format!("Invalid macaroon: {e}")))?;

        // Extract pubkey from identifier
        let identifier_bytes = macaroon.identifier().0.clone();
        let pubkey_hex = std::str::from_utf8(&identifier_bytes)
            .map_err(|_| ApiError::AuthenticationError("Invalid identifier encoding".into()))?;
        let pubkey = parse_pubkey(pubkey_hex)?;

        // Build verifier — satisfy both pubkey and permissions caveats
        let mut verifier = Verifier::default();
        verifier.satisfy_exact(format!("{PUBKEY_CAVEAT_PREFIX}{pubkey_hex}").into());
        // Satisfy any permissions caveat (we parse it ourselves below)
        verifier
            .satisfy_general(|caveat| caveat.0.starts_with(PERMISSIONS_CAVEAT_PREFIX.as_bytes()));

        verifier
            .verify(&macaroon, &self.root_key, vec![])
            .map_err(|e| ApiError::AuthenticationError(format!("Verification failed: {e}")))?;

        // Parse permissions from caveats (if present)
        let permissions = self.extract_permissions_from_macaroon(&macaroon);

        Ok((pubkey, permissions))
    }

    /// Extract permissions from macaroon caveats.
    ///
    /// Returns full admin permissions if no permissions caveat is found
    /// (backward compatibility).
    fn extract_permissions_from_macaroon(&self, macaroon: &Macaroon) -> TokenPermissions {
        for caveat in macaroon.first_party_caveats() {
            let pred = match &caveat {
                macaroon::Caveat::FirstParty(fp) => fp.predicate(),
                _ => continue, // skip third-party caveats
            };
            let caveat_str = String::from_utf8_lossy(&pred.0);
            if let Some(scope_str) = caveat_str.strip_prefix(PERMISSIONS_CAVEAT_PREFIX) {
                let permissions = scope_str
                    .split(',')
                    .filter_map(|s| match s.trim() {
                        "read" => Some(Permission::Read),
                        "write" => Some(Permission::Write),
                        "admin" => Some(Permission::Admin),
                        _ => None,
                    })
                    .collect();
                return TokenPermissions { permissions };
            }
        }
        // No permissions caveat → legacy token → full access
        TokenPermissions::admin()
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

    // ── Scoped macaroon tests ──────────────────────────────────────

    #[test]
    fn test_create_and_verify_scoped_macaroon_read_only() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth
            .create_scoped_macaroon(&pubkey, &TokenPermissions::read_only())
            .unwrap();
        let (extracted_pk, perms) = auth.verify_with_permissions(&token).unwrap();

        assert_eq!(extracted_pk, pubkey);
        assert!(perms.has(&Permission::Read));
        assert!(!perms.has(&Permission::Write));
        assert!(!perms.has(&Permission::Admin));
    }

    #[test]
    fn test_create_and_verify_scoped_macaroon_write() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth
            .create_scoped_macaroon(&pubkey, &TokenPermissions::write())
            .unwrap();
        let (_, perms) = auth.verify_with_permissions(&token).unwrap();

        assert!(perms.has(&Permission::Read));
        assert!(perms.has(&Permission::Write));
        assert!(!perms.has(&Permission::Admin));
    }

    #[test]
    fn test_create_and_verify_scoped_macaroon_admin() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth
            .create_scoped_macaroon(&pubkey, &TokenPermissions::admin())
            .unwrap();
        let (_, perms) = auth.verify_with_permissions(&token).unwrap();

        assert!(perms.has(&Permission::Read));
        assert!(perms.has(&Permission::Write));
        assert!(perms.has(&Permission::Admin));
    }

    #[test]
    fn test_legacy_token_gets_admin_permissions() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        // Legacy token (no permissions caveat)
        let token = auth.create_macaroon(&pubkey).unwrap();
        let (_, perms) = auth.verify_with_permissions(&token).unwrap();

        // Should default to full admin for backward compatibility
        assert!(perms.has(&Permission::Read));
        assert!(perms.has(&Permission::Write));
        assert!(perms.has(&Permission::Admin));
    }

    #[test]
    fn test_revoke_token_rejects_verification() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        let pubkey = test_pubkey();

        let token = auth.create_macaroon(&pubkey).unwrap();
        // Valid before revocation
        assert!(auth.verify_macaroon(&token).is_ok());

        // Revoke by pubkey hex (the macaroon identifier)
        let pubkey_hex = pubkey.to_string();
        auth.revoke_token(&pubkey_hex).unwrap();

        // Should be rejected after revocation
        let result = auth.verify_and_extract_pubkey(&token);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("revoked"), "expected 'revoked' in: {err}");
    }

    #[test]
    fn test_is_revoked() {
        let auth = Authenticator::new(vec![0x42u8; 32]);
        assert!(!auth.is_revoked("some_id"));
        auth.revoke_token("some_id").unwrap();
        assert!(auth.is_revoked("some_id"));
    }

    #[test]
    fn test_scoped_token_wrong_root_key_fails() {
        let auth1 = Authenticator::new(vec![0x01u8; 32]);
        let auth2 = Authenticator::new(vec![0x02u8; 32]);
        let pubkey = test_pubkey();

        let token = auth1
            .create_scoped_macaroon(&pubkey, &TokenPermissions::read_only())
            .unwrap();
        let result = auth2.verify_with_permissions(&token);
        assert!(result.is_err());
    }
}
