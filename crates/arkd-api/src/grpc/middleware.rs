//! gRPC authentication middleware
//!
//! Extracts authenticated user identity from request metadata and
//! attaches it as a request extension for downstream handlers.

use std::sync::Arc;

use bitcoin::secp256k1::XOnlyPublicKey;
use tonic::{Request, Status};
use tracing::{debug, warn};

use crate::auth::Authenticator;

/// Header name for the authentication token
pub const AUTH_HEADER: &str = "authorization";
/// Header prefix for bearer tokens
pub const BEARER_PREFIX: &str = "Bearer ";
/// Alternative header for macaroon tokens (compatibility with arkd Go)
pub const MACAROON_HEADER: &str = "macaroon";

/// Authenticated user identity attached to requests
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// The user's public key (x-only/Schnorr format)
    pub pubkey: XOnlyPublicKey,
    /// Whether this is a placeholder (unauthenticated) identity
    pub is_placeholder: bool,
}

impl AuthenticatedUser {
    /// Create a new authenticated user
    pub fn new(pubkey: XOnlyPublicKey) -> Self {
        Self {
            pubkey,
            is_placeholder: false,
        }
    }

    /// Create a placeholder for unauthenticated requests (dev mode only)
    pub fn placeholder() -> Self {
        // Use a well-known test pubkey — NEVER authorize real operations with this
        let bytes = [0x02u8; 32];
        let pubkey =
            XOnlyPublicKey::from_slice(&bytes).expect("static test pubkey should be valid");
        Self {
            pubkey,
            is_placeholder: true,
        }
    }
}

/// Authentication interceptor for gRPC requests
///
/// This middleware:
/// 1. Extracts auth tokens from request metadata (Authorization or macaroon header)
/// 2. Verifies the token using the configured authenticator
/// 3. Attaches the authenticated user's pubkey to request extensions
///
/// If authentication fails or is missing:
/// - In strict mode: rejects with UNAUTHENTICATED
/// - In permissive mode: attaches a placeholder (for dev/testing)
#[derive(Clone)]
pub struct AuthInterceptor {
    authenticator: Arc<Authenticator>,
    /// Whether to require authentication (false = permissive mode for dev)
    require_auth: bool,
}

impl AuthInterceptor {
    /// Create a new auth interceptor
    pub fn new(authenticator: Arc<Authenticator>, require_auth: bool) -> Self {
        Self {
            authenticator,
            require_auth,
        }
    }

    /// Create a permissive interceptor (dev mode — accepts unauthenticated requests)
    pub fn permissive(authenticator: Arc<Authenticator>) -> Self {
        Self::new(authenticator, false)
    }

    /// Create a strict interceptor (production — requires authentication)
    pub fn strict(authenticator: Arc<Authenticator>) -> Self {
        Self::new(authenticator, true)
    }

    /// Extract and verify authentication from a request
    #[allow(clippy::result_large_err)] // tonic::Status is inherently large
    pub fn authenticate<T>(&self, mut request: Request<T>) -> Result<Request<T>, Status> {
        // Try to extract token from headers
        let token = self.extract_token(&request);

        match token {
            Some(token) => {
                // Verify the token and extract pubkey
                match self.authenticator.verify_and_extract_pubkey(&token) {
                    Ok(pubkey) => {
                        debug!(pubkey = %pubkey, "Request authenticated");
                        request
                            .extensions_mut()
                            .insert(AuthenticatedUser::new(pubkey));
                        Ok(request)
                    }
                    Err(e) => {
                        warn!(error = %e, "Authentication failed");
                        Err(Status::unauthenticated(format!("Invalid token: {e}")))
                    }
                }
            }
            None if self.require_auth => {
                warn!("Missing authentication token");
                Err(Status::unauthenticated("Authentication required"))
            }
            None => {
                // Permissive mode — attach placeholder
                debug!("No auth token, using placeholder (dev mode)");
                request
                    .extensions_mut()
                    .insert(AuthenticatedUser::placeholder());
                Ok(request)
            }
        }
    }

    /// Extract auth token from request metadata
    fn extract_token<T>(&self, request: &Request<T>) -> Option<String> {
        let metadata = request.metadata();

        // Try Authorization: Bearer <token>
        if let Some(auth) = metadata.get(AUTH_HEADER) {
            if let Ok(value) = auth.to_str() {
                if let Some(token) = value.strip_prefix(BEARER_PREFIX) {
                    return Some(token.to_string());
                }
                // Also accept raw token without Bearer prefix
                if !value.is_empty() {
                    debug!("Auth token provided without Bearer prefix — consider using 'Authorization: Bearer <token>'");
                    return Some(value.to_string());
                }
            }
        }

        // Try macaroon header (Go arkd compatibility)
        if let Some(macaroon) = metadata.get(MACAROON_HEADER) {
            if let Ok(value) = macaroon.to_str() {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }

        None
    }
}

/// Helper to extract authenticated user from request extensions
pub fn get_authenticated_user<T>(request: &Request<T>) -> Option<&AuthenticatedUser> {
    request.extensions().get::<AuthenticatedUser>()
}

/// Helper to require authenticated user (returns error if missing or placeholder)
#[allow(clippy::result_large_err)] // tonic::Status is inherently large
pub fn require_authenticated_user<T>(request: &Request<T>) -> Result<&AuthenticatedUser, Status> {
    let user = get_authenticated_user(request)
        .ok_or_else(|| Status::unauthenticated("Not authenticated"))?;

    if user.is_placeholder {
        return Err(Status::unauthenticated(
            "Authentication required for this operation",
        ));
    }

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::metadata::MetadataValue;

    fn test_authenticator() -> Arc<Authenticator> {
        Arc::new(Authenticator::new(vec![0u8; 32]))
    }

    #[test]
    fn test_extract_bearer_token() {
        let interceptor = AuthInterceptor::permissive(test_authenticator());
        let mut request = Request::new(());
        request.metadata_mut().insert(
            AUTH_HEADER,
            MetadataValue::from_static("Bearer test_token_123"),
        );

        let token = interceptor.extract_token(&request);
        assert_eq!(token, Some("test_token_123".to_string()));
    }

    #[test]
    fn test_extract_macaroon_header() {
        let interceptor = AuthInterceptor::permissive(test_authenticator());
        let mut request = Request::new(());
        request.metadata_mut().insert(
            MACAROON_HEADER,
            MetadataValue::from_static("macaroon_value"),
        );

        let token = interceptor.extract_token(&request);
        assert_eq!(token, Some("macaroon_value".to_string()));
    }

    #[test]
    fn test_no_token_permissive() {
        let interceptor = AuthInterceptor::permissive(test_authenticator());
        let request = Request::new(());

        let result = interceptor.authenticate(request);
        assert!(result.is_ok());

        let req = result.unwrap();
        let user = get_authenticated_user(&req).unwrap();
        assert!(user.is_placeholder);
    }

    #[test]
    fn test_no_token_strict() {
        let interceptor = AuthInterceptor::strict(test_authenticator());
        let request = Request::new(());

        let result = interceptor.authenticate(request);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn test_authenticated_user_creation() {
        // Use a valid x-only pubkey (all 0x02 is valid for secp256k1)
        let bytes = [0x02u8; 32];
        let pubkey = XOnlyPublicKey::from_slice(&bytes).unwrap();
        let user = AuthenticatedUser::new(pubkey);

        assert!(!user.is_placeholder);
        assert_eq!(user.pubkey, pubkey);
    }

    #[test]
    fn test_placeholder_user() {
        let user = AuthenticatedUser::placeholder();
        assert!(user.is_placeholder);
    }
}
