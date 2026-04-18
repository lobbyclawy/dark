//! Bearer-token (macaroon) authentication middleware.
//!
//! When a root key is configured on `AppState`, bearer tokens are verified
//! against it via `dark_api::auth::Authenticator`. When no key is configured
//! and authentication is enabled, the middleware fails closed (401) — the
//! only escape hatches are `--auth-disabled` on the CLI or the unauthenticated
//! endpoints (`/ping`, `/openapi.json`, `/docs`).

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::AppState;

/// Opaque token extracted from the `Authorization` header.
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

/// Pubkey extracted from a verified macaroon.
#[derive(Clone, Debug)]
pub struct AuthenticatedPubkey(pub String);

/// Reject the request unless an `Authorization: Bearer <token>` header is
/// present and the token verifies against the configured macaroon root key.
pub async fn guard_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;

    if token.is_empty() {
        return Err(ApiError::Unauthorized("empty bearer token".into()));
    }

    match state.authenticator() {
        Some(auth) => {
            let pubkey = auth.verify_and_extract_pubkey(&token).map_err(|e| {
                ApiError::Unauthorized(format!("macaroon verification failed: {e}"))
            })?;
            req.extensions_mut()
                .insert(AuthenticatedPubkey(pubkey.to_string()));
        }
        None => {
            return Err(ApiError::Unauthorized(
                "server has no macaroon root key configured — start with \
                 --macaroon-root-key <hex|@path> or --auth-disabled"
                    .into(),
            ));
        }
    }

    req.extensions_mut().insert(BearerToken(token));
    Ok(next.run(req).await)
}
