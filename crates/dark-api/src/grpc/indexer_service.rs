//! IndexerService gRPC implementation — read-only querying API.
//!
//! Provides 13 RPCs for querying commitment transactions, VTXOs,
//! virtual transactions, assets, and script subscriptions.
//! `GetVtxos` is fully wired with pagination and filters.
//! Most RPCs delegate to the core IndexerService via round lookups.
//! Streaming subscriptions and a few advanced RPCs are stubbed with TODOs.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::proto::ark_v1::indexer_service_server::IndexerService as IndexerServiceTrait;
use crate::proto::ark_v1::{
    GetAssetRequest, GetAssetResponse, GetBatchSweepTransactionsRequest,
    GetBatchSweepTransactionsResponse, GetCommitmentTxRequest, GetCommitmentTxResponse,
    GetConnectorsRequest, GetConnectorsResponse, GetForfeitTxsRequest, GetForfeitTxsResponse,
    GetSubscriptionRequest, GetSubscriptionResponse, GetVirtualTxsRequest, GetVirtualTxsResponse,
    GetVtxoChainRequest, GetVtxoChainResponse, GetVtxoTreeLeavesRequest, GetVtxoTreeLeavesResponse,
    GetVtxoTreeRequest, GetVtxoTreeResponse, IndexerBatch, IndexerNode, IndexerOutpoint,
    IndexerPageResponse, IndexerServiceGetVtxosRequest, IndexerServiceGetVtxosResponse,
    IndexerSubscriptionEvent, IndexerVtxo, SubscribeForScriptsRequest, SubscribeForScriptsResponse,
    UnsubscribeForScriptsRequest, UnsubscribeForScriptsResponse,
};

/// In-memory store mapping subscription_id → set of subscribed scripts (hex pubkeys).
pub type SubscriptionStore = Arc<RwLock<HashMap<String, Vec<String>>>>;

/// Server-streaming response type for GetSubscription.
type GetSubscriptionStream =
    tokio_stream::wrappers::ReceiverStream<Result<GetSubscriptionResponse, Status>>;

/// Convert a core domain `Vtxo` to the proto `IndexerVtxo` message.
fn vtxo_to_proto(v: &dark_core::Vtxo) -> IndexerVtxo {
    IndexerVtxo {
        outpoint: Some(IndexerOutpoint {
            txid: v.outpoint.txid.clone(),
            vout: v.outpoint.vout,
        }),
        created_at: v.created_at,
        expires_at: v.expires_at,
        amount: v.amount,
        script: v.pubkey.clone(),
        is_preconfirmed: v.preconfirmed,
        is_swept: v.swept,
        is_unrolled: v.unrolled,
        is_spent: v.spent,
        spent_by: v.spent_by.clone(),
        commitment_txids: v.commitment_txids.clone(),
        settled_by: v.settled_by.clone(),
        ark_txid: v.ark_txid.clone(),
        assets: vec![],
    }
}

/// Apply pagination to a slice, returning (page_items, page_response).
fn paginate<T: Clone>(
    items: &[T],
    page_size: i32,
    page_index: i32,
) -> (Vec<T>, IndexerPageResponse) {
    let total = items.len() as i32;
    if total == 0 {
        return (
            vec![],
            IndexerPageResponse {
                current: 0,
                next: -1,
                total: 0,
            },
        );
    }

    let size = if page_size <= 0 { total } else { page_size };
    let idx = if page_index < 0 { 0 } else { page_index };
    let start = (idx * size) as usize;

    if start >= items.len() {
        return (
            vec![],
            IndexerPageResponse {
                current: idx,
                next: -1,
                total,
            },
        );
    }

    let end = std::cmp::min(start + size as usize, items.len());
    let page_items = items[start..end].to_vec();
    let next = if end < items.len() { idx + 1 } else { -1 };

    (
        page_items,
        IndexerPageResponse {
            current: idx,
            next,
            total,
        },
    )
}

/// IndexerService gRPC handler backed by the core application service.
///
/// Provides read-only RPCs for querying VTXOs, commitment transactions,
/// virtual transactions, connectors, assets, batch sweeps, and script
/// subscriptions. Mirrors the Go dark IndexerService proto definition.
pub struct IndexerGrpcService {
    core: Arc<dark_core::ArkService>,
    subscriptions: SubscriptionStore,
}

impl IndexerGrpcService {
    /// Create a new IndexerGrpcService wrapping the core service.
    pub fn new(core: Arc<dark_core::ArkService>, subscriptions: SubscriptionStore) -> Self {
        Self {
            core,
            subscriptions,
        }
    }
}

#[tonic::async_trait]
impl IndexerServiceTrait for IndexerGrpcService {
    type GetSubscriptionStream = GetSubscriptionStream;

    async fn get_commitment_tx(
        &self,
        request: Request<GetCommitmentTxRequest>,
    ) -> Result<Response<GetCommitmentTxResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetCommitmentTx called");

        let round = self
            .core
            .get_round_by_commitment_txid(&req.txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("No round found for commitment txid {}", req.txid))
            })?;

        // Build batch map — each round is treated as a single batch (index 0).
        // TODO(#237): Support multi-batch rounds once the schema tracks per-batch metadata.
        let mut batches = HashMap::new();

        // Count output VTXOs from the VTXO tree leaves (nodes with no children).
        let leaf_count = round
            .vtxo_tree
            .iter()
            .filter(|n| n.children.is_empty())
            .count() as i32;

        batches.insert(
            0u32,
            IndexerBatch {
                total_output_amount: 0, // TODO(#237): compute from tree leaf amounts
                total_output_vtxos: leaf_count,
                expires_at: round.vtxo_tree_expiration,
                swept: round.swept,
            },
        );

        // Count input VTXOs from intents
        let total_input_vtxos: i32 = round.intents.values().map(|i| i.inputs.len() as i32).sum();

        Ok(Response::new(GetCommitmentTxResponse {
            started_at: round.starting_timestamp,
            ended_at: round.ending_timestamp,
            batches,
            total_input_amount: 0, // TODO(#237): sum input VTXO amounts once available
            total_input_vtxos,
            total_output_amount: 0, // TODO(#237): sum output amounts from tree leaves
            total_output_vtxos: leaf_count,
        }))
    }

    async fn get_forfeit_txs(
        &self,
        request: Request<GetForfeitTxsRequest>,
    ) -> Result<Response<GetForfeitTxsResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetForfeitTxs called");

        let round = self
            .core
            .get_round_by_commitment_txid(&req.txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("No round found for commitment txid {}", req.txid))
            })?;

        let txids: Vec<String> = round.forfeit_txs.iter().map(|ft| ft.txid.clone()).collect();

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_txids, page_resp) = paginate(&txids, page_size, page_index);

        Ok(Response::new(GetForfeitTxsResponse {
            txids: page_txids,
            page: Some(page_resp),
        }))
    }

    async fn get_connectors(
        &self,
        request: Request<GetConnectorsRequest>,
    ) -> Result<Response<GetConnectorsResponse>, Status> {
        let req = request.into_inner();
        info!(txid = %req.txid, "IndexerService::GetConnectors called");

        let round = self
            .core
            .get_round_by_commitment_txid(&req.txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!("No round found for commitment txid {}", req.txid))
            })?;

        let connectors: Vec<IndexerNode> = round
            .connectors
            .iter()
            .map(|n| IndexerNode {
                txid: n.txid.clone(),
                children: n.children.iter().map(|(k, v)| (*k, v.clone())).collect(),
            })
            .collect();

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_items, page_resp) = paginate(&connectors, page_size, page_index);

        Ok(Response::new(GetConnectorsResponse {
            connectors: page_items,
            page: Some(page_resp),
        }))
    }

    async fn get_vtxo_tree(
        &self,
        request: Request<GetVtxoTreeRequest>,
    ) -> Result<Response<GetVtxoTreeResponse>, Status> {
        let req = request.into_inner();
        info!("IndexerService::GetVtxoTree called");

        let batch_txid = req
            .batch_outpoint
            .as_ref()
            .map(|o| o.txid.as_str())
            .unwrap_or("");

        if batch_txid.is_empty() {
            return Err(Status::invalid_argument("batch_outpoint.txid is required"));
        }

        // The batch outpoint txid is the commitment txid for the round.
        let round = self
            .core
            .get_round_by_commitment_txid(batch_txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "No round found for batch outpoint txid {}",
                    batch_txid
                ))
            })?;

        let tree_nodes: Vec<IndexerNode> = round
            .vtxo_tree
            .iter()
            .map(|n| IndexerNode {
                txid: n.txid.clone(),
                children: n.children.iter().map(|(k, v)| (*k, v.clone())).collect(),
            })
            .collect();

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_items, page_resp) = paginate(&tree_nodes, page_size, page_index);

        Ok(Response::new(GetVtxoTreeResponse {
            vtxo_tree: page_items,
            page: Some(page_resp),
        }))
    }

    async fn get_vtxo_tree_leaves(
        &self,
        request: Request<GetVtxoTreeLeavesRequest>,
    ) -> Result<Response<GetVtxoTreeLeavesResponse>, Status> {
        let req = request.into_inner();
        info!("IndexerService::GetVtxoTreeLeaves called");

        let batch_txid = req
            .batch_outpoint
            .as_ref()
            .map(|o| o.txid.as_str())
            .unwrap_or("");

        if batch_txid.is_empty() {
            return Err(Status::invalid_argument("batch_outpoint.txid is required"));
        }

        let round = self
            .core
            .get_round_by_commitment_txid(batch_txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "No round found for batch outpoint txid {}",
                    batch_txid
                ))
            })?;

        // Leaves are VTXO tree nodes with no children.
        // Return them as outpoints (txid, vout=0 as default).
        // TODO(#237): Track actual vout for leaf VTXO outpoints in the tree schema.
        let leaves: Vec<IndexerOutpoint> = round
            .vtxo_tree
            .iter()
            .filter(|n| n.children.is_empty())
            .map(|n| IndexerOutpoint {
                txid: n.txid.clone(),
                vout: 0,
            })
            .collect();

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_items, page_resp) = paginate(&leaves, page_size, page_index);

        Ok(Response::new(GetVtxoTreeLeavesResponse {
            leaves: page_items,
            page: Some(page_resp),
        }))
    }

    /// List VTXOs filtered by scripts (owner pubkeys) or outpoints.
    ///
    /// Scripts are treated as owner pubkeys; the first non-empty script is
    /// used to filter the indexer. Supports pagination and time-range filters.
    async fn get_vtxos(
        &self,
        request: Request<IndexerServiceGetVtxosRequest>,
    ) -> Result<Response<IndexerServiceGetVtxosResponse>, Status> {
        let req = request.into_inner();
        info!(
            scripts = req.scripts.len(),
            outpoints = req.outpoints.len(),
            "IndexerService::GetVtxos called"
        );

        // Scripts are P2TR scriptpubkeys: "5120<32-byte-tapkey-hex>" (68 hex chars).
        // Our VTXOs are indexed by the 64-char tapkey (no "5120" prefix).
        // Extract the tapkey from each script and filter by it.
        let script_tapkeys: Vec<String> = req
            .scripts
            .iter()
            .map(|s| {
                // P2TR: OP_1(51) OP_PUSH32(20) <32-byte-key> = 34 bytes = 68 hex chars
                if s.len() == 68 && s.starts_with("5120") {
                    s[4..].to_string()
                } else {
                    s.clone()
                }
            })
            .collect();
        let pubkey_filter = script_tapkeys.first().map(|s| s.as_str());

        info!(
            raw_scripts = ?req.scripts,
            extracted_tapkeys = ?script_tapkeys,
            pubkey_filter = ?pubkey_filter,
            "GetVtxos: script → tapkey extraction"
        );

        let vtxos = self
            .core
            .list_vtxos(pubkey_filter)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        info!(
            vtxo_count = vtxos.len(),
            "GetVtxos: vtxos returned from store"
        );

        // Apply client-requested filters.
        let filtered: Vec<IndexerVtxo> = vtxos
            .iter()
            .filter(|v| {
                if req.spendable_only {
                    return !v.spent && !v.swept;
                }
                if req.spent_only {
                    return v.spent;
                }
                if req.pending_only {
                    return v.preconfirmed;
                }
                if req.recoverable_only {
                    // Recoverable VTXOs: unrolled (published on-chain) but not yet swept.
                    return v.unrolled && !v.swept;
                }
                true
            })
            .filter(|v| {
                // Outpoint filter: skip VTXOs not in the requested set.
                if req.outpoints.is_empty() {
                    return true;
                }
                let key = format!("{}:{}", v.outpoint.txid, v.outpoint.vout);
                req.outpoints.contains(&key)
            })
            .filter(|v| {
                // Time-range filters
                if req.after > 0 && v.created_at <= req.after {
                    return false;
                }
                if req.before > 0 && v.created_at >= req.before {
                    return false;
                }
                true
            })
            .map(vtxo_to_proto)
            .collect();

        // Apply pagination
        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_vtxos, page_resp) = paginate(&filtered, page_size, page_index);

        Ok(Response::new(IndexerServiceGetVtxosResponse {
            vtxos: page_vtxos,
            page: Some(page_resp),
        }))
    }

    async fn get_vtxo_chain(
        &self,
        request: Request<GetVtxoChainRequest>,
    ) -> Result<Response<GetVtxoChainResponse>, Status> {
        let req = request.into_inner();
        let outpoint_str = req
            .outpoint
            .as_ref()
            .map(|o| format!("{}:{}", o.txid, o.vout))
            .unwrap_or_default();
        info!(outpoint = %outpoint_str, "IndexerService::GetVtxoChain called");

        // Look up the VTXO by outpoint to find its commitment chain.
        // TODO(#237): Implement full chain traversal (walk spent_by links) once
        // the indexer tracks VTXO spend chains end-to-end.
        let vtxo = self
            .core
            .list_vtxos(None)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .into_iter()
            .find(|v| {
                req.outpoint
                    .as_ref()
                    .map(|o| v.outpoint.txid == o.txid && v.outpoint.vout == o.vout)
                    .unwrap_or(false)
            });

        // For now, return the VTXO's commitment chain as single-hop entries.
        let chain: Vec<crate::proto::ark_v1::IndexerChain> = match vtxo {
            Some(v) => v
                .commitment_txids
                .iter()
                .map(|txid| crate::proto::ark_v1::IndexerChain {
                    txid: txid.clone(),
                    expires_at: v.expires_at,
                    r#type: 1, // INDEXER_CHAINED_TX_TYPE_COMMITMENT
                    spends: vec![],
                })
                .collect(),
            None => vec![],
        };

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_items, page_resp) = paginate(&chain, page_size, page_index);

        Ok(Response::new(GetVtxoChainResponse {
            chain: page_items,
            page: Some(page_resp),
        }))
    }

    async fn get_virtual_txs(
        &self,
        request: Request<GetVirtualTxsRequest>,
    ) -> Result<Response<GetVirtualTxsResponse>, Status> {
        let req = request.into_inner();
        info!(
            txids = req.txids.len(),
            "IndexerService::GetVirtualTxs called"
        );

        // Search all rounds' vtxo_tree for matching txids.
        // The vtxo_tree field of each Round holds TreeNode entries with txid + tx (base64 PSBT).
        let mut txs: Vec<String> = Vec::new();
        let target_txids: std::collections::HashSet<&str> =
            req.txids.iter().map(|s| s.as_str()).collect();

        if !target_txids.is_empty() {
            // Scan all rounds (paginated in batches of 100)
            let mut offset = 0u32;
            loop {
                let rounds = self.core.list_rounds(offset, 100).await.unwrap_or_default();
                if rounds.is_empty() {
                    break;
                }
                for round in &rounds {
                    for node in &round.vtxo_tree {
                        if !node.tx.is_empty() && target_txids.contains(node.txid.as_str()) {
                            txs.push(node.tx.clone());
                        }
                    }
                    // Also search connector tree
                    for node in &round.connectors {
                        if !node.tx.is_empty() && target_txids.contains(node.txid.as_str()) {
                            txs.push(node.tx.clone());
                        }
                    }
                }
                offset += 100;
                if rounds.len() < 100 {
                    break;
                }
            }
            info!(
                requested = req.txids.len(),
                found = txs.len(),
                "GetVirtualTxs: searched rounds for tree node PSBTs"
            );
        }

        let (page_size, page_index) = req
            .page
            .as_ref()
            .map(|p| (p.size, p.index))
            .unwrap_or((0, 0));

        let (page_items, page_resp) = paginate(&txs, page_size, page_index);

        Ok(Response::new(GetVirtualTxsResponse {
            txs: page_items,
            page: Some(page_resp),
        }))
    }

    async fn get_asset(
        &self,
        request: Request<GetAssetRequest>,
    ) -> Result<Response<GetAssetResponse>, Status> {
        let req = request.into_inner();
        info!(asset_id = %req.asset_id, "IndexerService::GetAsset called");

        let asset = self
            .core
            .get_asset(&req.asset_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        match asset {
            Some(a) => {
                let metadata_json = serde_json::to_string(&a.metadata).unwrap_or_default();
                Ok(Response::new(GetAssetResponse {
                    asset_id: a.asset_id,
                    supply: a.amount.to_string(),
                    metadata: metadata_json,
                    control_asset: String::new(),
                }))
            }
            None => Err(Status::not_found(format!(
                "Asset {} not found",
                req.asset_id
            ))),
        }
    }

    async fn get_batch_sweep_transactions(
        &self,
        request: Request<GetBatchSweepTransactionsRequest>,
    ) -> Result<Response<GetBatchSweepTransactionsResponse>, Status> {
        let req = request.into_inner();
        info!("IndexerService::GetBatchSweepTransactions called");

        let batch_txid = req
            .batch_outpoint
            .as_ref()
            .map(|o| o.txid.as_str())
            .unwrap_or("");

        if batch_txid.is_empty() {
            return Err(Status::invalid_argument("batch_outpoint.txid is required"));
        }

        let round = self
            .core
            .get_round_by_commitment_txid(batch_txid)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "No round found for batch outpoint txid {}",
                    batch_txid
                ))
            })?;

        // sweep_txs is a map of txid -> raw tx. Return the txids.
        let swept_by: Vec<String> = round.sweep_txs.keys().cloned().collect();

        Ok(Response::new(GetBatchSweepTransactionsResponse {
            swept_by,
        }))
    }

    async fn subscribe_for_scripts(
        &self,
        request: Request<SubscribeForScriptsRequest>,
    ) -> Result<Response<SubscribeForScriptsResponse>, Status> {
        let req = request.into_inner();
        let subscription_id = if req.subscription_id.is_empty() {
            format!(
                "sub-{:x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        } else {
            req.subscription_id
        };

        info!(
            scripts = req.scripts.len(),
            subscription_id = %subscription_id,
            "IndexerService::SubscribeForScripts — storing scripts"
        );

        // Store the subscribed scripts
        {
            let mut store = self.subscriptions.write().await;
            let entry = store.entry(subscription_id.clone()).or_default();
            for script in req.scripts {
                if !entry.contains(&script) {
                    entry.push(script);
                }
            }
        }

        Ok(Response::new(SubscribeForScriptsResponse {
            subscription_id,
        }))
    }

    async fn unsubscribe_for_scripts(
        &self,
        request: Request<UnsubscribeForScriptsRequest>,
    ) -> Result<Response<UnsubscribeForScriptsResponse>, Status> {
        let req = request.into_inner();
        info!(
            subscription_id = %req.subscription_id,
            "IndexerService::UnsubscribeForScripts called"
        );

        let mut store = self.subscriptions.write().await;
        if req.scripts.is_empty() {
            // Remove entire subscription
            store.remove(&req.subscription_id);
        } else {
            // Remove specific scripts
            if let Some(scripts) = store.get_mut(&req.subscription_id) {
                scripts.retain(|s| !req.scripts.contains(s));
                if scripts.is_empty() {
                    store.remove(&req.subscription_id);
                }
            }
        }

        Ok(Response::new(UnsubscribeForScriptsResponse {}))
    }

    async fn get_subscription(
        &self,
        request: Request<GetSubscriptionRequest>,
    ) -> Result<Response<Self::GetSubscriptionStream>, Status> {
        let req = request.into_inner();
        info!(
            subscription_id = %req.subscription_id,
            "IndexerService::GetSubscription called"
        );

        // Look up the subscribed scripts for this subscription
        let scripts = {
            let store = self.subscriptions.read().await;
            store.get(&req.subscription_id).cloned().unwrap_or_default()
        };

        if scripts.is_empty() {
            info!(
                subscription_id = %req.subscription_id,
                "No scripts found for subscription — stream will wait for subscribe_for_scripts"
            );
        }

        // Subscribe to the domain event bus
        let mut event_rx = self
            .core
            .subscribe_events()
            .await
            .map_err(|e| Status::internal(format!("Failed to subscribe to events: {e}")))?;

        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let subscriptions = Arc::clone(&self.subscriptions);
        let sub_id = req.subscription_id.clone();
        let core = Arc::clone(&self.core);

        // Spawn a task that listens for domain events and forwards matching ones
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(event) => {
                        match &event {
                            dark_core::domain::ArkEvent::VtxoCreated {
                                vtxo_id,
                                pubkey,
                                amount,
                                round_id,
                            } => {
                                // Re-read scripts each time in case they were updated
                                let current_scripts = {
                                    let store = subscriptions.read().await;
                                    store.get(&sub_id).cloned().unwrap_or_default()
                                };

                                // Check if this VTXO's pubkey matches any subscribed script.
                                // Go SDK subscribes with P2TR scripts: "5120<pubkey_hex>"
                                let p2tr_script = format!("5120{}", pubkey);
                                if current_scripts.is_empty()
                                    || !current_scripts
                                        .iter()
                                        .any(|s| s == pubkey || s == &p2tr_script)
                                {
                                    continue;
                                }

                                info!(
                                    subscription_id = %sub_id,
                                    vtxo_id = %vtxo_id,
                                    pubkey = %pubkey,
                                    amount = %amount,
                                    round_id = %round_id,
                                    "Matching VtxoCreated event — sending to subscriber"
                                );

                                // Fetch the full VTXO from the repo for proto conversion
                                let parts: Vec<&str> = vtxo_id.splitn(2, ':').collect();
                                let new_vtxos = if parts.len() == 2 {
                                    let outpoint = dark_core::VtxoOutpoint::new(
                                        parts[0].to_string(),
                                        parts[1].parse().unwrap_or(0),
                                    );
                                    match core.get_vtxos(&[outpoint]).await {
                                        Ok(vtxos) => vtxos.iter().map(vtxo_to_proto).collect(),
                                        Err(_) => vec![],
                                    }
                                } else {
                                    vec![]
                                };

                                let response = GetSubscriptionResponse {
                                    data: Some(
                                        crate::proto::ark_v1::get_subscription_response::Data::Event(
                                            IndexerSubscriptionEvent {
                                                txid: String::new(),
                                                scripts: vec![pubkey.clone()],
                                                new_vtxos,
                                                spent_vtxos: vec![],
                                                tx: String::new(),
                                                checkpoint_txs: HashMap::new(),
                                                swept_vtxos: vec![],
                                            },
                                        ),
                                    ),
                                };

                                if tx.send(Ok(response)).await.is_err() {
                                    info!(
                                        subscription_id = %sub_id,
                                        "Subscriber disconnected — stopping event listener"
                                    );
                                    return;
                                }
                            }
                            _ => {
                                // Ignore non-VTXO events for now
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            subscription_id = %sub_id,
                            lagged = n,
                            "Event stream lagged — some events may have been missed"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!(
                            subscription_id = %sub_id,
                            "Event bus closed — ending subscription stream"
                        );
                        return;
                    }
                }
            }
        });

        Ok(Response::new(GetSubscriptionStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtxo_to_proto_mapping() {
        let v = dark_core::Vtxo {
            outpoint: dark_core::VtxoOutpoint {
                txid: "abc123".to_string(),
                vout: 0,
            },
            amount: 100_000,
            pubkey: "deadbeef".to_string(),
            commitment_txids: vec!["txid1".to_string()],
            root_commitment_txid: "txid1".to_string(),
            settled_by: "settle_txid".to_string(),
            spent_by: String::new(),
            ark_txid: String::new(),
            spent: false,
            unrolled: false,
            swept: false,
            preconfirmed: false,
            expires_at: 9999,
            created_at: 1000,
        };

        let proto = vtxo_to_proto(&v);
        assert_eq!(proto.amount, 100_000);
        assert_eq!(proto.script, "deadbeef");
        assert!(!proto.is_spent);
        assert!(!proto.is_swept);
        assert!(!proto.is_preconfirmed);
        assert_eq!(proto.expires_at, 9999);
        assert_eq!(proto.created_at, 1000);
        assert_eq!(proto.commitment_txids, vec!["txid1"]);
        assert_eq!(proto.settled_by, "settle_txid");
        let op = proto.outpoint.unwrap();
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 0);
    }

    #[test]
    fn test_vtxo_to_proto_spent_flags() {
        let v = dark_core::Vtxo {
            outpoint: dark_core::VtxoOutpoint {
                txid: "def".to_string(),
                vout: 1,
            },
            amount: 50_000,
            pubkey: "pk".to_string(),
            commitment_txids: vec![],
            root_commitment_txid: String::new(),
            settled_by: String::new(),
            spent_by: "spend_tx".to_string(),
            ark_txid: String::new(),
            spent: true,
            unrolled: false,
            swept: true,
            preconfirmed: false,
            expires_at: 0,
            created_at: 0,
        };

        let proto = vtxo_to_proto(&v);
        assert!(proto.is_spent);
        assert!(proto.is_swept);
        assert_eq!(proto.spent_by, "spend_tx");
    }

    #[test]
    fn test_paginate_empty() {
        let items: Vec<String> = vec![];
        let (page, resp) = paginate(&items, 10, 0);
        assert!(page.is_empty());
        assert_eq!(resp.total, 0);
        assert_eq!(resp.next, -1);
    }

    #[test]
    fn test_paginate_single_page() {
        let items = vec!["a", "b", "c"];
        let (page, resp) = paginate(&items, 10, 0);
        assert_eq!(page.len(), 3);
        assert_eq!(resp.total, 3);
        assert_eq!(resp.current, 0);
        assert_eq!(resp.next, -1);
    }

    #[test]
    fn test_paginate_multiple_pages() {
        let items = vec!["a", "b", "c", "d", "e"];
        let (page, resp) = paginate(&items, 2, 0);
        assert_eq!(page, vec!["a", "b"]);
        assert_eq!(resp.total, 5);
        assert_eq!(resp.current, 0);
        assert_eq!(resp.next, 1);

        let (page2, resp2) = paginate(&items, 2, 1);
        assert_eq!(page2, vec!["c", "d"]);
        assert_eq!(resp2.next, 2);

        let (page3, resp3) = paginate(&items, 2, 2);
        assert_eq!(page3, vec!["e"]);
        assert_eq!(resp3.next, -1);
    }

    #[test]
    fn test_paginate_out_of_bounds() {
        let items = vec!["a", "b"];
        let (page, resp) = paginate(&items, 10, 5);
        assert!(page.is_empty());
        assert_eq!(resp.next, -1);
    }
}
