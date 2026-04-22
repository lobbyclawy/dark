//! Data-transfer objects exposed on the REST surface.
//!
//! Shadow a subset of `dark_client::types` + proto types with
//! `utoipa::ToSchema` derives so the OpenAPI spec carries rich type info.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use dark_client::types as ct;

// ── Info ───────────────────────────────────────────────────────────────────

/// Server info response. Mirrors `ark.v1.GetInfoResponse`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServerInfoDto {
    pub pubkey: String,
    pub forfeit_pubkey: String,
    pub network: String,
    pub session_duration: u32,
    pub unilateral_exit_delay: u32,
    pub boarding_exit_delay: u32,
    pub version: String,
    pub dust: u64,
    pub vtxo_min_amount: u64,
    pub vtxo_max_amount: u64,
}

impl From<ct::ServerInfo> for ServerInfoDto {
    fn from(v: ct::ServerInfo) -> Self {
        Self {
            pubkey: v.pubkey,
            forfeit_pubkey: v.forfeit_pubkey,
            network: v.network,
            session_duration: v.session_duration,
            unilateral_exit_delay: v.unilateral_exit_delay,
            boarding_exit_delay: v.boarding_exit_delay,
            version: v.version,
            dust: v.dust,
            vtxo_min_amount: v.vtxo_min_amount,
            vtxo_max_amount: v.vtxo_max_amount,
        }
    }
}

// ── VTXOs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssetDto {
    pub asset_id: String,
    pub amount: u64,
}

impl From<ct::Asset> for AssetDto {
    fn from(a: ct::Asset) -> Self {
        Self {
            asset_id: a.asset_id,
            amount: a.amount,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VtxoDto {
    /// "{txid}:{vout}" identifier.
    pub id: String,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub is_spent: bool,
    pub is_swept: bool,
    pub is_unrolled: bool,
    pub spent_by: String,
    pub ark_txid: String,
    pub assets: Vec<AssetDto>,
}

impl From<ct::Vtxo> for VtxoDto {
    fn from(v: ct::Vtxo) -> Self {
        Self {
            id: v.id,
            txid: v.txid,
            vout: v.vout,
            amount: v.amount,
            script: v.script,
            created_at: v.created_at,
            expires_at: v.expires_at,
            is_spent: v.is_spent,
            is_swept: v.is_swept,
            is_unrolled: v.is_unrolled,
            spent_by: v.spent_by,
            ark_txid: v.ark_txid,
            assets: v.assets.into_iter().map(AssetDto::from).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListVtxosResponse {
    pub vtxos: Vec<VtxoDto>,
}

// ── Rounds ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoundSummaryDto {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
}

impl From<ct::RoundSummary> for RoundSummaryDto {
    fn from(r: ct::RoundSummary) -> Self {
        Self {
            id: r.id,
            starting_timestamp: r.starting_timestamp,
            ending_timestamp: r.ending_timestamp,
            stage: r.stage,
            commitment_txid: r.commitment_txid,
            failed: r.failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoundInfoDto {
    pub id: String,
    pub starting_timestamp: i64,
    pub ending_timestamp: i64,
    pub stage: String,
    pub commitment_txid: String,
    pub failed: bool,
    pub intent_count: u32,
}

impl From<ct::RoundInfo> for RoundInfoDto {
    fn from(r: ct::RoundInfo) -> Self {
        Self {
            id: r.id,
            starting_timestamp: r.starting_timestamp,
            ending_timestamp: r.ending_timestamp,
            stage: r.stage,
            commitment_txid: r.commitment_txid,
            failed: r.failed,
            intent_count: r.intent_count,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ListRoundsResponse {
    pub rounds: Vec<RoundSummaryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PageInfo {
    pub current: i32,
    pub next: i32,
    pub total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IndexerNodeDto {
    pub txid: String,
    /// Map of child-index → child txid. Keys are stringified u32 so the value
    /// is JSON-compatible (all JSON object keys must be strings).
    pub children: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VtxoTreeResponse {
    pub vtxo_tree: Vec<IndexerNodeDto>,
    pub page: Option<PageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BatchInfoDto {
    pub total_output_amount: u64,
    pub total_output_vtxos: i32,
    pub expires_at: i64,
    pub swept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CommitmentTxResponse {
    pub started_at: i64,
    pub ended_at: i64,
    pub total_input_amount: u64,
    pub total_input_vtxos: i32,
    pub total_output_amount: u64,
    pub total_output_vtxos: i32,
    /// Batches indexed by batch-id (stringified u32).
    pub batches: HashMap<String, BatchInfoDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VtxoChainEntryDto {
    pub txid: String,
    pub expires_at: i64,
    pub chained_type: String,
    pub spends: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VtxoChainResponse {
    pub chain: Vec<VtxoChainEntryDto>,
    pub page: Option<PageInfo>,
}

// ── Off-chain tx (async) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubmitTxRequestDto {
    /// Signed Ark virtual tx, hex encoded.
    pub signed_ark_tx: String,
    /// Checkpoint transactions in hex (optional).
    #[serde(default)]
    pub checkpoint_txs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SubmitTxResponseDto {
    pub ark_txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FinalizeTxRequestDto {
    #[serde(default)]
    pub final_checkpoint_txs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingTxResponseDto {
    pub ark_txid: String,
    pub status: String,
}

// ── Intents ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterIntentRequestDto {
    /// BIP-322 proof PSBT (hex).
    pub proof: String,
    /// Canonical intent message (JSON text per the BIP-322 proof).
    pub message: String,
    /// Optional delegate pubkey (hex-encoded compressed). Empty string if absent.
    #[serde(default)]
    pub delegate_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterIntentResponseDto {
    pub intent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfirmRegistrationRequestDto {
    pub intent_id: String,
}

/// One output destination: exactly one of `vtxo_script` or `onchain_address`
/// must be set.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OutputDto {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub vtxo_script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub onchain_address: Option<String>,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EstimateIntentFeeRequestDto {
    pub input_vtxo_ids: Vec<String>,
    pub outputs: Vec<OutputDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EstimateIntentFeeResponseDto {
    pub fee_sats: u64,
    pub fee_rate_sats_per_vb: u64,
}

// ── Exit ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestExitRequestDto {
    /// On-chain destination (bech32m P2TR).
    pub onchain_address: String,
    pub amount: u64,
    /// `"txid:vout"` list of VTXOs to spend.
    pub vtxo_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestExitResponseDto {
    pub exit_id: String,
}

// ── Events (SSE payloads) ──────────────────────────────────────────────────

/// Batch-lifecycle event carried over `/v1/events`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BatchEventDto {
    BatchStarted {
        round_id: String,
        timestamp: i64,
    },
    BatchFinalization {
        round_id: String,
        timestamp: i64,
        min_relay_fee_rate: i64,
    },
    BatchFinalized {
        round_id: String,
        txid: String,
    },
    BatchFailed {
        round_id: String,
        reason: String,
    },
    TreeSigningStarted {
        round_id: String,
        cosigner_pubkeys: Vec<String>,
        timestamp: i64,
    },
    TreeTx {
        round_id: String,
        txid: String,
    },
    TreeNoncesAggregated {
        round_id: String,
        timestamp: i64,
    },
    Heartbeat {
        timestamp: i64,
    },
}

impl From<ct::BatchEvent> for BatchEventDto {
    fn from(ev: ct::BatchEvent) -> Self {
        match ev {
            ct::BatchEvent::BatchStarted {
                round_id,
                timestamp,
            } => Self::BatchStarted {
                round_id,
                timestamp,
            },
            ct::BatchEvent::BatchFinalization {
                round_id,
                timestamp,
                min_relay_fee_rate,
            } => Self::BatchFinalization {
                round_id,
                timestamp,
                min_relay_fee_rate,
            },
            ct::BatchEvent::BatchFinalized { round_id, txid } => {
                Self::BatchFinalized { round_id, txid }
            }
            ct::BatchEvent::BatchFailed { round_id, reason } => {
                Self::BatchFailed { round_id, reason }
            }
            ct::BatchEvent::TreeSigningStarted {
                round_id,
                cosigner_pubkeys,
                timestamp,
            } => Self::TreeSigningStarted {
                round_id,
                cosigner_pubkeys,
                timestamp,
            },
            ct::BatchEvent::TreeTx { round_id, txid } => Self::TreeTx { round_id, txid },
            ct::BatchEvent::TreeNoncesAggregated {
                round_id,
                timestamp,
            } => Self::TreeNoncesAggregated {
                round_id,
                timestamp,
            },
            ct::BatchEvent::Heartbeat { timestamp } => Self::Heartbeat { timestamp },
        }
    }
}

/// Transaction-stream event carried over `/v1/transactions/events`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TxEventDto {
    CommitmentTx {
        txid: String,
        round_id: String,
        timestamp: i64,
    },
    ArkTx {
        txid: String,
        from_script: String,
        to_script: String,
        amount: u64,
        timestamp: i64,
    },
    Heartbeat {
        timestamp: i64,
    },
}

impl From<ct::TxEvent> for TxEventDto {
    fn from(ev: ct::TxEvent) -> Self {
        match ev {
            ct::TxEvent::CommitmentTx {
                txid,
                round_id,
                timestamp,
            } => Self::CommitmentTx {
                txid,
                round_id,
                timestamp,
            },
            ct::TxEvent::ArkTx {
                txid,
                from_script,
                to_script,
                amount,
                timestamp,
            } => Self::ArkTx {
                txid,
                from_script,
                to_script,
                amount,
                timestamp,
            },
            ct::TxEvent::Heartbeat { timestamp } => Self::Heartbeat { timestamp },
        }
    }
}
