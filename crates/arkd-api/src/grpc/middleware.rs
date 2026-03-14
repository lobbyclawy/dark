//! gRPC authentication middleware
//!
//! Extracts authenticated user identity from request metadata and
//! attaches it as a request extension for downstream handlers.

use std::sync::Arc;

use bitcoin::secp256k1::XOnlyPublicKey;
use tonic::{Request, Status};
use tracing::{debug, warn};

use crate::auth::{Authenticator, Permission, TokenPermissions};

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
    /// Permission scopes granted by the token
    pub permissions: TokenPermissions,
}

impl AuthenticatedUser {
    /// Create a new authenticated user with the given permissions
    pub fn new(pubkey: XOnlyPublicKey, permissions: TokenPermissions) -> Self {
        Self {
            pubkey,
            is_placeholder: false,
            permissions,
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
            permissions: TokenPermissions::admin(), // dev mode gets full access
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
                // Verify the token and extract pubkey + permissions
                match self.authenticator.verify_with_permissions(&token) {
                    Ok((pubkey, permissions)) => {
                        debug!(pubkey = %pubkey, ?permissions, "Request authenticated");
                        request
                            .extensions_mut()
                            .insert(AuthenticatedUser::new(pubkey, permissions));
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

/// Determine the required [`Permission`] for a gRPC method path.
///
/// The path follows the pattern `/package.Service/MethodName`.
/// Returns `None` for unknown methods (caller decides policy).
pub fn required_permission_for_path(path: &str) -> Option<Permission> {
    // Extract the method name (last segment after '/')
    let method = path.rsplit('/').next().unwrap_or("");

    // AdminService — everything is Admin
    if path.contains("AdminService") {
        return Some(Permission::Admin);
    }

    match method {
        // Read-only RPCs
        "GetInfo" | "GetVtxos" | "ListRounds" | "GetRound" | "GetEventStream" | "GetPendingTx"
        | "UpdateStreamTopics" | "EstimateIntentFee" => Some(Permission::Read),

        // Mutation RPCs
        "RegisterForRound" | "SubmitTx" | "FinalizeTx" | "RequestExit" | "DeleteIntent" => {
            Some(Permission::Write)
        }

        // Admin RPCs (explicit method names outside AdminService path)
        "GetStatus" | "GetRoundDetails" | "GetRounds" => Some(Permission::Admin),

        _ => None,
    }
}

/// Check that the authenticated user has the required permission for the
/// given gRPC method path. Returns `Status::permission_denied` on failure.
#[allow(clippy::result_large_err)]
pub fn check_permission(user: &AuthenticatedUser, method_path: &str) -> Result<(), Status> {
    if let Some(required) = required_permission_for_path(method_path) {
        if !user.permissions.has(&required) {
            return Err(Status::permission_denied(format!(
                "Token lacks required permission: {required:?}"
            )));
        }
    }
    Ok(())
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
        let user = AuthenticatedUser::new(pubkey, TokenPermissions::admin());

        assert!(!user.is_placeholder);
        assert_eq!(user.pubkey, pubkey);
        assert!(user.permissions.has(&Permission::Admin));
    }

    #[test]
    fn test_placeholder_user() {
        let user = AuthenticatedUser::placeholder();
        assert!(user.is_placeholder);
        // Placeholder has full admin access in dev mode
        assert!(user.permissions.has(&Permission::Admin));
    }

    // ── Permission scope tests ─────────────────────────────────────

    #[test]
    fn test_permission_read_allows_get_info() {
        let perms = TokenPermissions::read_only();
        assert!(perms.has(&Permission::Read));
        assert_eq!(
            required_permission_for_path("/ark.v1.ArkService/GetInfo"),
            Some(Permission::Read)
        );
    }

    #[test]
    fn test_permission_write_allows_register_for_round() {
        let perms = TokenPermissions::write();
        assert!(perms.has(&Permission::Write));
        assert_eq!(
            required_permission_for_path("/ark.v1.ArkService/RegisterForRound"),
            Some(Permission::Write)
        );
    }

    #[test]
    fn test_permission_read_denies_register_for_round() {
        let bytes = [0x02u8; 32];
        let pubkey = XOnlyPublicKey::from_slice(&bytes).unwrap();
        let user = AuthenticatedUser::new(pubkey, TokenPermissions::read_only());

        let result = check_permission(&user, "/ark.v1.ArkService/RegisterForRound");
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn test_admin_has_all_permissions() {
        let perms = TokenPermissions::admin();
        assert!(perms.has(&Permission::Read));
        assert!(perms.has(&Permission::Write));
        assert!(perms.has(&Permission::Admin));
    }

    #[test]
    fn test_read_only_token_permissions() {
        let perms = TokenPermissions::read_only();
        assert!(perms.has(&Permission::Read));
        assert!(!perms.has(&Permission::Write));
        assert!(!perms.has(&Permission::Admin));
    }

    #[test]
    fn test_admin_service_requires_admin() {
        assert_eq!(
            required_permission_for_path("/ark.v1.AdminService/GetStatus"),
            Some(Permission::Admin)
        );
        assert_eq!(
            required_permission_for_path("/ark.v1.AdminService/GetRoundDetails"),
            Some(Permission::Admin)
        );
    }

    #[test]
    fn test_check_permission_allows_matching_scope() {
        let bytes = [0x02u8; 32];
        let pubkey = XOnlyPublicKey::from_slice(&bytes).unwrap();
        let user = AuthenticatedUser::new(pubkey, TokenPermissions::write());

        // Write token can read
        assert!(check_permission(&user, "/ark.v1.ArkService/GetInfo").is_ok());
        // Write token can write
        assert!(check_permission(&user, "/ark.v1.ArkService/SubmitTx").is_ok());
        // Write token cannot admin
        assert!(check_permission(&user, "/ark.v1.AdminService/GetStatus").is_err());
    }
}
