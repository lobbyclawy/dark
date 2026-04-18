//! v1 REST surface.

pub mod events;
pub mod exits;
pub mod info;
pub mod intents;
pub mod playground;
pub mod rounds;
pub mod txs;
pub mod vtxos;

use axum::Router;
use utoipa::OpenApi;

use crate::state::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        info::get_info,
        vtxos::list_vtxos,
        vtxos::vtxo_chain,
        rounds::list_rounds,
        rounds::get_round,
        rounds::get_tree,
        rounds::get_commitment_tx,
        txs::submit_tx,
        txs::finalize_tx,
        txs::get_tx,
        txs::query_pending_txs,
        intents::register_intent,
        intents::delete_intent,
        intents::confirm_intent,
        intents::estimate_fee,
        exits::request_exit,
        events::events_stream,
        events::transactions_stream,
        playground::create_session,
        playground::get_session,
        playground::faucet,
    ),
    components(schemas(
        crate::dto::ServerInfoDto,
        crate::dto::AssetDto,
        crate::dto::VtxoDto,
        crate::dto::ListVtxosResponse,
        crate::dto::RoundSummaryDto,
        crate::dto::RoundInfoDto,
        crate::dto::ListRoundsResponse,
        crate::dto::PageInfo,
        crate::dto::IndexerNodeDto,
        crate::dto::VtxoTreeResponse,
        crate::dto::BatchInfoDto,
        crate::dto::CommitmentTxResponse,
        crate::dto::VtxoChainEntryDto,
        crate::dto::VtxoChainResponse,
        crate::dto::SubmitTxRequestDto,
        crate::dto::SubmitTxResponseDto,
        crate::dto::FinalizeTxRequestDto,
        crate::dto::PendingTxResponseDto,
        crate::dto::RegisterIntentRequestDto,
        crate::dto::RegisterIntentResponseDto,
        crate::dto::ConfirmRegistrationRequestDto,
        crate::dto::OutputDto,
        crate::dto::EstimateIntentFeeRequestDto,
        crate::dto::EstimateIntentFeeResponseDto,
        crate::dto::RequestExitRequestDto,
        crate::dto::RequestExitResponseDto,
        crate::dto::BatchEventDto,
        crate::dto::TxEventDto,
        crate::api::v1::txs::IntentFilterDto,
        crate::api::v1::txs::PendingTxsResponse,
        crate::api::v1::playground::CreateSessionResponse,
        crate::api::v1::playground::SessionView,
        crate::api::v1::playground::FaucetRequest,
        crate::api::v1::playground::FaucetResponse,
        crate::error::ProblemDetails,
    )),
    tags(
        (name = "info",       description = "Server info and parameters."),
        (name = "vtxos",      description = "Virtual UTXO inspection."),
        (name = "rounds",     description = "Round history and VTXO trees."),
        (name = "txs",        description = "Off-chain Ark transactions (async flow)."),
        (name = "intents",    description = "Batched round-settlement intents."),
        (name = "exits",      description = "Unilateral / collaborative exit to on-chain."),
        (name = "events",     description = "Server-streamed lifecycle events (SSE)."),
        (name = "playground", description = "Session + faucet helpers (playground only)."),
    )
)]
pub struct V1ApiDoc;

/// Build the full `/v1` Router.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(info::router())
        .merge(vtxos::router())
        .merge(rounds::router())
        .merge(txs::router())
        .merge(intents::router())
        .merge(exits::router())
        .merge(events::router())
        .merge(playground::router())
}
