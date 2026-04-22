//! `/v1/events` and `/v1/transactions/events` — Server-Sent Events streams.
//!
//! Maps the gRPC server-streaming RPCs to `text/event-stream`:
//! - `GET /v1/events`              ⇒ `ArkService.GetEventStream`
//! - `GET /v1/transactions/events` ⇒ `ArkService.GetTransactionsStream`
//!
//! Each SSE message carries a JSON-encoded `BatchEventDto` (resp. `TxEventDto`)
//! in the `data` field and the variant name as the `event` field so clients
//! can filter via `EventSource.addEventListener(eventName, …)`.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::Router;
use futures::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use crate::dto::{BatchEventDto, TxEventDto};
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/events", get(events_stream))
        .route("/transactions/events", get(transactions_stream))
}

#[utoipa::path(
    get,
    path = "/events",
    tag = "events",
    summary = "Subscribe to batch lifecycle events (SSE)",
    description = "Opens a `text/event-stream` carrying the batch lifecycle: \
                   `batch_started`, `batch_finalization`, `batch_finalized`, `batch_failed`, \
                   `tree_signing_started`, `tree_tx`, `tree_nonces_aggregated`, `heartbeat`. \
                   Each message has the variant name as its `event` and a JSON `BatchEventDto` \
                   as its `data`.",
    responses(
        (status = 200, description = "text/event-stream of BatchEventDto"),
        (status = 502, description = "Upstream error")
    )
)]
pub async fn events_stream(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let (rx, _cancel) = {
        let mut ark = state.ark().await;
        ark.get_event_stream(None)
            .await
            .map_err(|e| ApiError::Upstream(format!("GetEventStream: {e}")))?
    };

    let stream = ReceiverStream::new(rx).map(|ev| {
        let dto = BatchEventDto::from(ev);
        let event_name = batch_event_name(&dto);
        let data = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".into());
        Ok(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

#[utoipa::path(
    get,
    path = "/transactions/events",
    tag = "events",
    summary = "Subscribe to transaction events (SSE)",
    description = "Opens a `text/event-stream` carrying `commitment_tx`, `ark_tx`, and \
                   `heartbeat` events as they appear on-chain or in-server.",
    responses(
        (status = 200, description = "text/event-stream of TxEventDto"),
        (status = 502, description = "Upstream error")
    )
)]
pub async fn transactions_stream(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let (rx, _cancel) = {
        let mut ark = state.ark().await;
        ark.get_transactions_stream()
            .await
            .map_err(|e| ApiError::Upstream(format!("GetTransactionsStream: {e}")))?
    };

    let stream = ReceiverStream::new(rx).map(|ev| {
        let dto = TxEventDto::from(ev);
        let event_name = tx_event_name(&dto);
        let data = serde_json::to_string(&dto).unwrap_or_else(|_| "{}".into());
        Ok(Event::default().event(event_name).data(data))
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn batch_event_name(ev: &BatchEventDto) -> &'static str {
    match ev {
        BatchEventDto::BatchStarted { .. } => "batch_started",
        BatchEventDto::BatchFinalization { .. } => "batch_finalization",
        BatchEventDto::BatchFinalized { .. } => "batch_finalized",
        BatchEventDto::BatchFailed { .. } => "batch_failed",
        BatchEventDto::TreeSigningStarted { .. } => "tree_signing_started",
        BatchEventDto::TreeTx { .. } => "tree_tx",
        BatchEventDto::TreeNoncesAggregated { .. } => "tree_nonces_aggregated",
        BatchEventDto::Heartbeat { .. } => "heartbeat",
    }
}

fn tx_event_name(ev: &TxEventDto) -> &'static str {
    match ev {
        TxEventDto::CommitmentTx { .. } => "commitment_tx",
        TxEventDto::ArkTx { .. } => "ark_tx",
        TxEventDto::Heartbeat { .. } => "heartbeat",
    }
}
