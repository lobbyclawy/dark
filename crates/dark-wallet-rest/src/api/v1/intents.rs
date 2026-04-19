//! `/v1/intents` — round-settlement intents (BIP-322 based).

use axum::extract::{Path, State};
use axum::routing::{delete, post};
use axum::{Json, Router};

use dark_api::proto::ark_v1::{
    output::Destination, ConfirmRegistrationRequest, EstimateIntentFeeRequest,
    Intent as ProtoIntent, Output as ProtoOutput, RegisterIntentRequest,
};

use crate::dto::{
    ConfirmRegistrationRequestDto, EstimateIntentFeeRequestDto, EstimateIntentFeeResponseDto,
    OutputDto, RegisterIntentRequestDto, RegisterIntentResponseDto,
};
use crate::error::{ApiError, ApiResult, ProblemDetails};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/intents", post(register_intent))
        .route("/intents/{id}", delete(delete_intent))
        .route("/intents/{id}/confirm", post(confirm_intent))
        .route("/intents/{id}/fee", post(estimate_fee))
}

#[utoipa::path(
    post,
    path = "/intents",
    tag = "intents",
    summary = "Register a round-settlement intent",
    description = "Registers a BIP-322-signed intent for the next round. The body carries the \
                   proof PSBT (hex) and a canonical JSON `message`; optionally a \
                   `delegate_pubkey` (hex compressed) for delegated submission.",
    request_body = RegisterIntentRequestDto,
    responses(
        (status = 200, description = "Accepted", body = RegisterIntentResponseDto),
        (status = 400, description = "Malformed request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn register_intent(
    State(state): State<AppState>,
    Json(req): Json<RegisterIntentRequestDto>,
) -> ApiResult<Json<RegisterIntentResponseDto>> {
    if req.proof.is_empty() {
        return Err(ApiError::BadRequest("proof must not be empty".into()));
    }
    if req.message.is_empty() {
        return Err(ApiError::BadRequest("message must not be empty".into()));
    }

    let mut client = state.ark_raw().await;
    let resp = client
        .register_intent(RegisterIntentRequest {
            intent: Some(ProtoIntent {
                proof: req.proof,
                message: req.message,
                delegate_pubkey: req.delegate_pubkey,
            }),
        })
        .await
        .map_err(|e| ApiError::Upstream(format!("RegisterIntent: {e}")))?
        .into_inner();

    Ok(Json(RegisterIntentResponseDto {
        intent_id: resp.intent_id,
    }))
}

#[utoipa::path(
    delete,
    path = "/intents/{id}",
    tag = "intents",
    summary = "Delete a registered intent",
    params(("id" = String, Path, description = "Intent id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn delete_intent(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<axum::http::StatusCode> {
    let mut ark = state.ark().await;
    ark.delete_intent(&id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/intents/{id}/confirm",
    tag = "intents",
    summary = "Confirm participation in the current batch",
    description = "Called after a `BatchStarted` event to acknowledge the VTXO tree.",
    params(("id" = String, Path, description = "Intent id")),
    request_body = ConfirmRegistrationRequestDto,
    responses(
        (status = 204, description = "Confirmed"),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn confirm_intent(
    State(state): State<AppState>,
    Path(_id): Path<String>,
    Json(req): Json<ConfirmRegistrationRequestDto>,
) -> ApiResult<axum::http::StatusCode> {
    let mut client = state.ark_raw().await;
    client
        .confirm_registration(ConfirmRegistrationRequest {
            intent_id: req.intent_id,
        })
        .await
        .map_err(|e| ApiError::Upstream(format!("ConfirmRegistration: {e}")))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/intents/{id}/fee",
    tag = "intents",
    summary = "Estimate the fee for a proposed intent",
    description = "Takes the input VTXO ids and output destinations and returns the server's \
                   fee estimate. The path `{id}` is unused today but kept for symmetry with \
                   per-intent endpoints.",
    params(("id" = String, Path, description = "Intent id — unused")),
    request_body = EstimateIntentFeeRequestDto,
    responses(
        (status = 200, description = "Fee estimate", body = EstimateIntentFeeResponseDto),
        (status = 400, description = "Bad request", body = ProblemDetails),
        (status = 502, description = "Upstream error", body = ProblemDetails),
    )
)]
pub async fn estimate_fee(
    State(state): State<AppState>,
    Path(_id): Path<String>,
    Json(req): Json<EstimateIntentFeeRequestDto>,
) -> ApiResult<Json<EstimateIntentFeeResponseDto>> {
    let outputs = req
        .outputs
        .into_iter()
        .map(dto_to_output)
        .collect::<ApiResult<Vec<_>>>()?;

    let mut client = state.ark_raw().await;
    let resp = client
        .estimate_intent_fee(EstimateIntentFeeRequest {
            input_vtxo_ids: req.input_vtxo_ids,
            outputs,
        })
        .await
        .map_err(|e| ApiError::Upstream(format!("EstimateIntentFee: {e}")))?
        .into_inner();

    Ok(Json(EstimateIntentFeeResponseDto {
        fee_sats: resp.fee_sats,
        fee_rate_sats_per_vb: resp.fee_rate_sats_per_vb,
    }))
}

fn dto_to_output(o: OutputDto) -> ApiResult<ProtoOutput> {
    let destination = match (o.vtxo_script, o.onchain_address) {
        (Some(s), None) => Destination::VtxoScript(s),
        (None, Some(a)) => Destination::OnchainAddress(a),
        (Some(_), Some(_)) => {
            return Err(ApiError::BadRequest(
                "output must have exactly one of vtxo_script or onchain_address".into(),
            ));
        }
        (None, None) => {
            return Err(ApiError::BadRequest(
                "output must specify vtxo_script or onchain_address".into(),
            ));
        }
    };
    Ok(ProtoOutput {
        destination: Some(destination),
        amount: o.amount,
    })
}
