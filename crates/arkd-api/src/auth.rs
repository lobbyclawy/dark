//! Authentication middleware (macaroons)

use crate::{ApiError, ApiResult};

/// Macaroon-based authenticator
///
/// Compatible with original arkd authentication.
pub struct Authenticator {
    /// Root macaroon secret
    root_key: Vec<u8>,
}

impl Authenticator {
    /// Create a new authenticator with the given root key
    pub fn new(root_key: Vec<u8>) -> Self {
        Self { root_key }
    }

    /// Create a new macaroon for a user
    pub fn create_macaroon(&self, _user_id: &str) -> ApiResult<String> {
        // TODO: Implement macaroon creation in issue #9
        Err(ApiError::InternalError(
            "Macaroon creation not yet implemented".to_string(),
        ))
    }

    /// Verify a macaroon token
    pub fn verify_macaroon(&self, _token: &str) -> ApiResult<bool> {
        // TODO: Implement macaroon verification in issue #9
        Err(ApiError::InternalError(
            "Macaroon verification not yet implemented".to_string(),
        ))
    }

    /// Extract user ID from a verified macaroon
    pub fn extract_user_id(&self, _token: &str) -> ApiResult<String> {
        // TODO: Implement in issue #9
        Err(ApiError::InternalError(
            "User extraction not yet implemented".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticator_creation() {
        let auth = Authenticator::new(vec![0u8; 32]);
        assert_eq!(auth.root_key.len(), 32);
    }
}
