/**
 * This file is machine-generated from
 * `crates/dark-wallet-rest/openapi.json` via `openapi-typescript`.
 *
 * It is hand-curated in this commit — run `npm run generate` (or
 * `just generate-rest-ts-client`) to regenerate from the spec.
 *
 * DO NOT EDIT BY HAND beyond keeping it aligned with the Rust DTOs.
 */

export interface paths {
  "/ping": { get: { responses: { 200: { content: { "text/plain": string } } } } };
  "/openapi.json": { get: { responses: { 200: { content: { "application/json": unknown } } } } };
  "/v1/info": { get: { responses: { 200: { content: { "application/json": components["schemas"]["ServerInfoDto"] } } } } };
  "/v1/vtxos": { get: { responses: { 200: { content: { "application/json": components["schemas"]["ListVtxosResponse"] } } } } };
  "/v1/vtxos/{outpoint}/chain": { get: { responses: { 200: { content: { "application/json": components["schemas"]["VtxoChainResponse"] } } } } };
  "/v1/rounds": { get: { responses: { 200: { content: { "application/json": components["schemas"]["ListRoundsResponse"] } } } } };
  "/v1/rounds/{id}": { get: { responses: { 200: { content: { "application/json": components["schemas"]["RoundInfoDto"] } } } } };
  "/v1/rounds/{id}/tree": { get: { responses: { 200: { content: { "application/json": components["schemas"]["VtxoTreeResponse"] } } } } };
  "/v1/rounds/{id}/commitment-tx": { get: { responses: { 200: { content: { "application/json": components["schemas"]["CommitmentTxResponse"] } } } } };
  "/v1/txs": { post: { responses: { 200: { content: { "application/json": components["schemas"]["SubmitTxResponseDto"] } } } } };
  "/v1/txs/query": { post: { responses: { 200: { content: { "application/json": components["schemas"]["PendingTxsResponse"] } } } } };
  "/v1/txs/{id}": { get: { responses: { 200: { content: { "application/json": components["schemas"]["PendingTxResponseDto"] } } } } };
  "/v1/txs/{id}/finalize": { post: { responses: { 204: never } } };
  "/v1/intents": { post: { responses: { 200: { content: { "application/json": components["schemas"]["RegisterIntentResponseDto"] } } } } };
  "/v1/intents/{id}": { delete: { responses: { 204: never } } };
  "/v1/intents/{id}/confirm": { post: { responses: { 204: never } } };
  "/v1/intents/{id}/fee": { post: { responses: { 200: { content: { "application/json": components["schemas"]["EstimateIntentFeeResponseDto"] } } } } };
  "/v1/exits": { post: { responses: { 200: { content: { "application/json": components["schemas"]["RequestExitResponseDto"] } } } } };
  "/v1/events": { get: { responses: { 200: { content: { "text/event-stream": unknown } } } } };
  "/v1/transactions/events": { get: { responses: { 200: { content: { "text/event-stream": unknown } } } } };
  "/v1/playground/session": { post: { responses: { 200: { content: { "application/json": components["schemas"]["CreateSessionResponse"] } } } } };
  "/v1/playground/session/{id}": { get: { responses: { 200: { content: { "application/json": components["schemas"]["SessionView"] } } } } };
  "/v1/playground/faucet": { post: { responses: { 200: { content: { "application/json": components["schemas"]["FaucetResponse"] } } } } };
}

export interface components {
  schemas: {
    ProblemDetails: { title: string; status: number; detail: string };

    ServerInfoDto: {
      pubkey: string;
      forfeit_pubkey: string;
      network: string;
      session_duration: number;
      unilateral_exit_delay: number;
      boarding_exit_delay: number;
      version: string;
      dust: number;
      vtxo_min_amount: number;
      vtxo_max_amount: number;
    };

    AssetDto: { asset_id: string; amount: number };
    VtxoDto: {
      id: string;
      txid: string;
      vout: number;
      amount: number;
      script: string;
      created_at: number;
      expires_at: number;
      is_spent: boolean;
      is_swept: boolean;
      is_unrolled: boolean;
      spent_by: string;
      ark_txid: string;
      assets: components["schemas"]["AssetDto"][];
    };
    ListVtxosResponse: { vtxos: components["schemas"]["VtxoDto"][] };

    RoundSummaryDto: {
      id: string;
      starting_timestamp: number;
      ending_timestamp: number;
      stage: string;
      commitment_txid: string;
      failed: boolean;
    };
    RoundInfoDto: components["schemas"]["RoundSummaryDto"] & { intent_count: number };
    ListRoundsResponse: { rounds: components["schemas"]["RoundSummaryDto"][] };

    PageInfo: { current: number; next: number; total: number };
    IndexerNodeDto: { txid: string; children: Record<string, string> };
    VtxoTreeResponse: {
      vtxo_tree: components["schemas"]["IndexerNodeDto"][];
      page?: components["schemas"]["PageInfo"] | null;
    };
    BatchInfoDto: {
      total_output_amount: number;
      total_output_vtxos: number;
      expires_at: number;
      swept: boolean;
    };
    CommitmentTxResponse: {
      started_at: number;
      ended_at: number;
      total_input_amount: number;
      total_input_vtxos: number;
      total_output_amount: number;
      total_output_vtxos: number;
      batches: Record<string, components["schemas"]["BatchInfoDto"]>;
    };
    VtxoChainEntryDto: {
      txid: string;
      expires_at: number;
      chained_type: string;
      spends: string[];
    };
    VtxoChainResponse: {
      chain: components["schemas"]["VtxoChainEntryDto"][];
      page?: components["schemas"]["PageInfo"] | null;
    };

    SubmitTxRequestDto: { signed_ark_tx: string; checkpoint_txs?: string[] };
    SubmitTxResponseDto: { ark_txid: string };
    FinalizeTxRequestDto: { final_checkpoint_txs?: string[] };
    PendingTxResponseDto: { ark_txid: string; status: string };
    PendingTxsResponse: { pending_txs: components["schemas"]["PendingTxResponseDto"][] };
    IntentFilterDto: { proof: string; message: string; delegate_pubkey?: string };

    RegisterIntentRequestDto: {
      proof: string;
      message: string;
      delegate_pubkey?: string;
    };
    RegisterIntentResponseDto: { intent_id: string };
    ConfirmRegistrationRequestDto: { intent_id: string };
    OutputDto: {
      vtxo_script?: string;
      onchain_address?: string;
      amount: number;
    };
    EstimateIntentFeeRequestDto: {
      input_vtxo_ids: string[];
      outputs: components["schemas"]["OutputDto"][];
    };
    EstimateIntentFeeResponseDto: {
      fee_sats: number;
      fee_rate_sats_per_vb: number;
    };

    RequestExitRequestDto: {
      onchain_address: string;
      amount: number;
      vtxo_ids: string[];
    };
    RequestExitResponseDto: { exit_id: string };

    BatchEventDto:
      | ({ type: "batch_started" } & { round_id: string; timestamp: number })
      | ({ type: "batch_finalization" } & {
          round_id: string;
          timestamp: number;
          min_relay_fee_rate: number;
        })
      | ({ type: "batch_finalized" } & { round_id: string; txid: string })
      | ({ type: "batch_failed" } & { round_id: string; reason: string })
      | ({ type: "tree_signing_started" } & {
          round_id: string;
          cosigner_pubkeys: string[];
          timestamp: number;
        })
      | ({ type: "tree_tx" } & { round_id: string; txid: string })
      | ({ type: "tree_nonces_aggregated" } & {
          round_id: string;
          timestamp: number;
        })
      | ({ type: "heartbeat" } & { timestamp: number });
    TxEventDto:
      | ({ type: "commitment_tx" } & {
          txid: string;
          round_id: string;
          timestamp: number;
        })
      | ({ type: "ark_tx" } & {
          txid: string;
          from_script: string;
          to_script: string;
          amount: number;
          timestamp: number;
        })
      | ({ type: "heartbeat" } & { timestamp: number });

    CreateSessionResponse: {
      session_id: string;
      pubkey_hex: string;
      privkey_hex: string;
      boarding_address: string;
      created_at: number;
    };
    SessionView: {
      session_id: string;
      pubkey_hex: string;
      boarding_address: string;
      created_at: number;
      faucet_drips: number;
    };
    FaucetRequest: { session_id: string };
    FaucetResponse: {
      boarding_address: string;
      drips_remaining: number;
      note: string;
    };
  };
}
