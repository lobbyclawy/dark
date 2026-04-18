//! `/v1/playground` — session + faucet helpers for the playground deployment.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::secp256k1::{rand, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::{AppState, PlaygroundSession};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/playground/session", post(create_session))
        .route("/playground/session/{id}", get(get_session))
        .route("/playground/faucet", post(faucet))
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub pubkey_hex: String,
    /// Hex-encoded secret key. **Only returned once**, at session creation.
    pub privkey_hex: String,
    pub boarding_address: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SessionView {
    pub session_id: String,
    pub pubkey_hex: String,
    pub boarding_address: String,
    pub created_at: i64,
    pub faucet_drips: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FaucetRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FaucetResponse {
    pub boarding_address: String,
    pub drips_remaining: u32,
    pub note: String,
}

const FAUCET_DRIP_CAP: u32 = 5;

#[utoipa::path(
    post,
    path = "/playground/session",
    tag = "playground",
    summary = "Mint a playground session",
    description = "Generates a fresh secp256k1 keypair, derives a boarding \
                   address via `ArkService.GetInfo`, and returns both to the \
                   caller. The secret key is returned **only once**.",
    responses(
        (status = 200, description = "Session minted", body = CreateSessionResponse),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn create_session(
    State(state): State<AppState>,
) -> ApiResult<Json<CreateSessionResponse>> {
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut rand::thread_rng());
    let xonly = sk.x_only_public_key(&secp).0;
    let pubkey_hex = xonly.to_string();
    let privkey_hex = hex::encode(sk.secret_bytes());

    let (_onchain, _offchain, boarding) = {
        let mut ark = state.ark().await;
        ark.receive(&pubkey_hex).await?
    };
    let boarding_address = boarding.address;

    let session_id = Uuid::new_v4().to_string();
    let created_at = unix_now();

    let session = PlaygroundSession {
        session_id: session_id.clone(),
        pubkey_hex: pubkey_hex.clone(),
        privkey_hex: privkey_hex.clone(),
        boarding_address: boarding_address.clone(),
        created_at,
        faucet_drips: 0,
    };
    state
        .sessions_write()
        .await
        .insert(session_id.clone(), session);

    Ok(Json(CreateSessionResponse {
        session_id,
        pubkey_hex,
        privkey_hex,
        boarding_address,
        created_at,
    }))
}

#[utoipa::path(
    get,
    path = "/playground/session/{id}",
    tag = "playground",
    summary = "Look up a session (no secret key)",
    params(("id" = String, Path, description = "Session id")),
    responses(
        (status = 200, description = "Session details", body = SessionView),
        (status = 404, description = "Unknown session", body = ProblemDetails),
    )
)]
pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<SessionView>> {
    let sessions = state.sessions_read().await;
    let s = sessions
        .get(&id)
        .ok_or_else(|| ApiError::NotFound(format!("session {id}")))?;
    Ok(Json(SessionView {
        session_id: s.session_id.clone(),
        pubkey_hex: s.pubkey_hex.clone(),
        boarding_address: s.boarding_address.clone(),
        created_at: s.created_at,
        faucet_drips: s.faucet_drips,
    }))
}

#[utoipa::path(
    post,
    path = "/playground/faucet",
    tag = "playground",
    summary = "Request a faucet drip (rate-limited)",
    description = "Returns the session's boarding address + remaining drip \
                   budget. The daemon does not broadcast on-chain — operators \
                   must run an external funding service.",
    request_body = FaucetRequest,
    responses(
        (status = 200, description = "Drip granted", body = FaucetResponse),
        (status = 404, description = "Unknown session", body = ProblemDetails),
        (status = 429, description = "Drip cap exceeded", body = ProblemDetails),
    )
)]
pub async fn faucet(
    State(state): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> ApiResult<Json<FaucetResponse>> {
    let mut sessions = state.sessions_write().await;
    let session = sessions
        .get_mut(&req.session_id)
        .ok_or_else(|| ApiError::NotFound(format!("session {}", req.session_id)))?;

    if session.faucet_drips >= FAUCET_DRIP_CAP {
        return Err(ApiError::TooManyRequests(format!(
            "faucet cap reached ({FAUCET_DRIP_CAP} drips)"
        )));
    }
    session.faucet_drips += 1;
    let drips_remaining = FAUCET_DRIP_CAP - session.faucet_drips;
    let boarding_address = session.boarding_address.clone();

    Ok(Json(FaucetResponse {
        boarding_address,
        drips_remaining,
        note: "Fund the returned boarding address via an external faucet or \
               operator-run regtest/signet bitcoind. This daemon does not \
               broadcast on-chain."
            .into(),
    }))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
