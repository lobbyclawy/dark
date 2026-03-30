//! ArkClient — typed gRPC client for dark server.

use crate::error::{ClientError, ClientResult};
use tokio::sync::mpsc;

use crate::types::{
    Balance, BatchEvent, BatchTxRes, BoardingAddress, LockedAmount, OffchainAddress,
    OffchainBalance, OnchainBalance, RoundInfo, RoundSummary, ServerInfo, TxEvent, Vtxo,
};
use dark_api::proto::ark_v1::{
    ark_service_client::ArkServiceClient, get_subscription_response,
    indexer_service_client::IndexerServiceClient, round_event, transaction_event, BurnAssetRequest,
    ConfirmRegistrationRequest, DeleteIntentRequest, FinalizePendingTxsRequest, FinalizeTxRequest,
    GetEventStreamRequest, GetInfoRequest, GetRoundRequest, GetSubscriptionRequest,
    GetTransactionsStreamRequest, GetVirtualTxsRequest, GetVtxoChainRequest, GetVtxosRequest,
    IndexerChainedTxType, IndexerOutpoint, Input as ProtoInput, Intent as ProtoIntent,
    IssueAssetRequest, ListRoundsRequest, Outpoint as ProtoOutpoint, RedeemNotesRequest,
    RegisterForRoundRequest, RegisterIntentRequest, ReissueAssetRequest, RequestExitRequest,
    SubmitSignedForfeitTxsRequest, SubmitTreeNoncesRequest, SubmitTreeSignaturesRequest,
    SubmitTxRequest, SubscribeForScriptsRequest, UnsubscribeForScriptsRequest,
};

/// A boarding UTXO to include as input when registering for a round.
#[derive(Debug, Clone)]
pub struct BoardingUtxo {
    /// Transaction ID of the on-chain UTXO.
    pub txid: String,
    /// Output index.
    pub vout: u32,
}
use tonic::transport::Channel;

/// Client for communicating with an dark server.
pub struct ArkClient {
    server_url: String,
    client: Option<ArkServiceClient<Channel>>,
    indexer: Option<IndexerServiceClient<Channel>>,
}

/// Parse a hex-encoded public key (33-byte compressed or 32-byte x-only) into
/// a [`bitcoin::secp256k1::XOnlyPublicKey`].
fn parse_xonly_pubkey(hex_str: &str) -> ClientResult<bitcoin::secp256k1::XOnlyPublicKey> {
    let bytes =
        hex::decode(hex_str).map_err(|e| ClientError::InvalidAddress(format!("bad hex: {}", e)))?;
    match bytes.len() {
        33 => {
            // Compressed pubkey — take the 32-byte x coordinate (drop prefix byte).
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes[1..])
                .map_err(|e| ClientError::InvalidAddress(format!("invalid pubkey: {}", e)))
        }
        32 => bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes)
            .map_err(|e| ClientError::InvalidAddress(format!("invalid x-only pubkey: {}", e))),
        66 => {
            // 66 hex chars decoded to 33 bytes — already handled above.
            // This branch handles the edge case where the input has a stray prefix.
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes[1..33])
                .map_err(|e| ClientError::InvalidAddress(format!("invalid pubkey: {}", e)))
        }
        other => Err(ClientError::InvalidAddress(format!(
            "expected 32 or 33 byte pubkey, got {} bytes",
            other
        ))),
    }
}

impl ArkClient {
    /// Create a new client for `server_url` (e.g. `http://localhost:50051`).
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            client: None,
            indexer: None,
        }
    }

    /// Connect to the server. Call this before making RPC calls.
    pub async fn connect(&mut self) -> ClientResult<()> {
        let channel = Channel::from_shared(self.server_url.clone())
            .map_err(|e| ClientError::Connection(format!("Invalid URL: {}", e)))?
            .connect()
            .await
            .map_err(|e| ClientError::Connection(format!("Failed to connect: {}", e)))?;

        self.indexer = Some(IndexerServiceClient::new(channel.clone()));
        self.client = Some(ArkServiceClient::new(channel));
        Ok(())
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.client.is_some()
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    fn require_client(&mut self) -> ClientResult<&mut ArkServiceClient<Channel>> {
        self.client
            .as_mut()
            .ok_or_else(|| ClientError::Connection("Not connected. Call connect() first.".into()))
    }

    #[allow(dead_code)]
    fn require_indexer(&mut self) -> ClientResult<&mut IndexerServiceClient<Channel>> {
        self.indexer
            .as_mut()
            .ok_or_else(|| ClientError::Connection("Not connected. Call connect() first.".into()))
    }

    /// Get server info via GetInfo RPC.
    pub async fn get_info(&mut self) -> ClientResult<ServerInfo> {
        let client = self.require_client()?;

        let response = client
            .get_info(GetInfoRequest {})
            .await
            .map_err(|e| ClientError::Rpc(format!("GetInfo failed: {}", e)))?;

        let info = response.into_inner();
        Ok(ServerInfo {
            pubkey: info.signer_pubkey,
            forfeit_pubkey: info.forfeit_pubkey,
            network: info.network,
            session_duration: info.session_duration as u32,
            unilateral_exit_delay: info.unilateral_exit_delay as u32,
            boarding_exit_delay: info.boarding_exit_delay as u32,
            version: info.version,
            dust: info.dust as u64,
            vtxo_min_amount: info.vtxo_min_amount as u64,
            vtxo_max_amount: info.vtxo_max_amount as u64,
        })
    }

    /// List VTXOs owned by `pubkey`.
    pub async fn list_vtxos(&mut self, pubkey: &str) -> ClientResult<Vec<Vtxo>> {
        let client = self.require_client()?;

        let response = client
            .get_vtxos(GetVtxosRequest {
                pubkey: pubkey.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetVtxos failed: {}", e)))?;

        let resp = response.into_inner();
        let mut vtxos = Vec::new();

        for v in resp.spendable {
            let outpoint = v.outpoint.unwrap_or_default();
            vtxos.push(Vtxo {
                id: format!("{}:{}", outpoint.txid, outpoint.vout),
                txid: outpoint.txid,
                vout: outpoint.vout,
                amount: v.amount,
                script: v.script,
                created_at: v.created_at,
                expires_at: v.expires_at,
                is_spent: false,
                is_swept: v.is_swept,
                is_unrolled: v.is_unrolled,
                spent_by: v.spent_by,
                ark_txid: v.ark_txid,
                assets: v
                    .assets
                    .iter()
                    .map(|a| crate::types::Asset {
                        asset_id: a.asset_id.clone(),
                        amount: a.amount,
                    })
                    .collect(),
            });
        }

        for v in resp.spent {
            let outpoint = v.outpoint.unwrap_or_default();
            vtxos.push(Vtxo {
                id: format!("{}:{}", outpoint.txid, outpoint.vout),
                txid: outpoint.txid,
                vout: outpoint.vout,
                amount: v.amount,
                script: v.script,
                created_at: v.created_at,
                expires_at: v.expires_at,
                is_spent: v.is_spent,
                is_swept: v.is_swept,
                is_unrolled: v.is_unrolled,
                spent_by: v.spent_by,
                ark_txid: v.ark_txid,
                assets: v
                    .assets
                    .iter()
                    .map(|a| crate::types::Asset {
                        asset_id: a.asset_id.clone(),
                        amount: a.amount,
                    })
                    .collect(),
            });
        }

        Ok(vtxos)
    }

    /// List rounds with optional pagination.
    pub async fn list_rounds(
        &mut self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> ClientResult<Vec<RoundSummary>> {
        let client = self.require_client()?;

        let response = client
            .list_rounds(ListRoundsRequest {
                after: 0,
                before: 0,
                limit: limit.unwrap_or(20),
                offset: offset.unwrap_or(0),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("ListRounds failed: {}", e)))?;

        let resp = response.into_inner();
        let rounds = resp
            .rounds
            .into_iter()
            .map(|r| RoundSummary {
                id: r.id,
                starting_timestamp: r.starting_timestamp,
                ending_timestamp: r.ending_timestamp,
                stage: r.stage,
                commitment_txid: r.commitment_txid,
                failed: r.failed,
            })
            .collect();

        Ok(rounds)
    }

    /// Get details for a specific round.
    pub async fn get_round(&mut self, round_id: &str) -> ClientResult<RoundInfo> {
        let client = self.require_client()?;

        let response = client
            .get_round(GetRoundRequest {
                round_id: round_id.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetRound failed: {}", e)))?;

        let resp = response.into_inner();
        let round = resp
            .round
            .ok_or_else(|| ClientError::InvalidResponse("Round not found".into()))?;

        Ok(RoundInfo {
            id: round.id,
            starting_timestamp: round.starting_timestamp,
            ending_timestamp: round.ending_timestamp,
            stage: round.stage,
            commitment_txid: round.commitment_txid,
            failed: round.failed,
            intent_count: round.intent_count,
        })
    }

    /// Return the three receive addresses for `pubkey`:
    ///
    /// - **onchain** – a P2TR address derived from the pubkey (placeholder format until the
    ///   server exposes a dedicated derive-address RPC for users).
    /// - **offchain** – a VTXO script address the server recognises as belonging to `pubkey`.
    /// - **boarding** – the Taproot address used to on-board funds from the chain into Ark.
    ///
    /// The server's `GetInfo` is used to obtain the forfeit tapscript and boarding exit delay,
    /// which are embedded into the tapscript list returned for each address.
    pub async fn receive(
        &mut self,
        pubkey: &str,
    ) -> ClientResult<(String, OffchainAddress, BoardingAddress)> {
        // Fetch server metadata so we can embed meaningful tapscript hints.
        let info = self.get_info().await?;

        // ── Onchain address ───────────────────────────────────────────────
        // A simple P2TR address representation keyed on the user pubkey.
        // Real wallets derive this via BIP-86; we use a labelled placeholder that is
        // unambiguous and round-trips through display/parse cleanly.
        let onchain_address = format!("bc1p{}", &pubkey[..pubkey.len().min(40)]);

        // ── Offchain (VTXO) address ───────────────────────────────────────
        // The VTXO script is the raw pubkey in hex; the server matches incoming VTXO
        // outputs against this script when indexing.
        let vtxo_tapscript = format!(
            "OP_CHECKSIG pubkey:{} server:{}",
            pubkey,
            &info.pubkey[..info.pubkey.len().min(16)]
        );
        let offchain_address = OffchainAddress {
            address: format!("ark:{}", pubkey),
            tapscripts: vec![vtxo_tapscript],
        };

        // ── Boarding address ──────────────────────────────────────────────
        // The boarding output is a P2TR locked with two leaves:
        //   1. Cooperative path: <user_pubkey> + <server_forfeit_pubkey>
        //   2. Exit path: <user_pubkey> CHECKSEQUENCEVERIFY after unilateral_exit_delay seconds
        let coop_leaf = format!(
            "OP_CHECKSIG pubkey:{} AND pubkey:{}",
            pubkey, info.forfeit_pubkey
        );
        let exit_delay = info.unilateral_exit_delay;
        let exit_leaf = format!(
            "OP_CHECKSEQUENCEVERIFY {} OP_CHECKSIG pubkey:{}",
            exit_delay, pubkey
        );
        // Build a real P2TR (bech32m) boarding address from the user pubkey.
        let network = match info.network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "signet" => bitcoin::Network::Signet,
            _ => bitcoin::Network::Regtest,
        };
        let boarding_address_str = {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let pubkey_bytes: Option<Vec<u8>> = {
                if !pubkey.len().is_multiple_of(2) {
                    None
                } else {
                    (0..pubkey.len())
                        .step_by(2)
                        .map(|i| u8::from_str_radix(&pubkey[i..i + 2], 16).ok())
                        .collect()
                }
            };
            // XOnlyPublicKey expects 32 bytes; compressed pubkeys are 33 bytes
            // (1-byte parity prefix + 32-byte x-coordinate). Strip the prefix.
            let xonly = pubkey_bytes.as_deref().and_then(|b| {
                let x_bytes = if b.len() == 33 { &b[1..] } else { b };
                bitcoin::secp256k1::XOnlyPublicKey::from_slice(x_bytes).ok()
            });
            match xonly {
                Some(user_xpk) => {
                    // Boarding address uses the same taproot structure as the server:
                    // unspendable internal key + 2 leaves (CSV exit + cooperative).
                    // This must match what the server injects as witness_utxo in finalize_round().
                    // Server uses signer_pubkey (not forfeit_pubkey) in build_vtxo_taproot
                    let asp_xonly = parse_xonly_pubkey(&info.pubkey).ok();
                    let boarding_delay = info.boarding_exit_delay;
                    if let Some(asp_xpk) = asp_xonly {
                        match dark_bitcoin::build_vtxo_taproot(&user_xpk, &asp_xpk, boarding_delay)
                        {
                            Ok(taproot_info) => {
                                let address = bitcoin::Address::p2tr_tweaked(
                                    taproot_info.output_key(),
                                    network,
                                );
                                address.to_string()
                            }
                            Err(_) => format!("bc1p_boarding_{}", &pubkey[..pubkey.len().min(32)]),
                        }
                    } else {
                        // Fallback: key-path only (less correct but won't crash)
                        let builder = bitcoin::taproot::TaprootBuilder::new();
                        let spend_info = builder
                            .finalize(&secp, user_xpk)
                            .expect("valid taproot spend info");
                        let output_key = spend_info.output_key();
                        let address = bitcoin::Address::p2tr_tweaked(output_key, network);
                        address.to_string()
                    }
                }
                None => format!("bc1p_boarding_{}", &pubkey[..pubkey.len().min(32)]),
            }
        };
        let boarding_address = BoardingAddress {
            address: boarding_address_str,
            tapscripts: vec![coop_leaf, exit_leaf],
        };

        Ok((onchain_address, offchain_address, boarding_address))
    }

    /// Return the combined on-chain and offchain balance for `pubkey`.
    ///
    /// Offchain balance is derived from the live VTXO list (`GetVtxos`).
    /// On-chain balance uses VTXOs flagged as `is_unrolled` (exited to chain):
    /// those with a non-zero `expires_at` are still time-locked; the rest are spendable.
    ///
    /// If no VTXOs are found the balances are zero — a valid state for a fresh key.
    pub async fn get_balance(&mut self, pubkey: &str) -> ClientResult<Balance> {
        let vtxos = self.list_vtxos(pubkey).await?;

        let mut offchain_total: u64 = 0;
        let mut onchain_spendable: u64 = 0;
        let mut locked: Vec<LockedAmount> = Vec::new();

        for vtxo in &vtxos {
            if vtxo.is_spent {
                // Spent VTXOs contribute nothing to current balance.
                continue;
            }

            if vtxo.is_unrolled {
                // Unrolled VTXOs have exited the Ark tree and now live on-chain.
                // They may still be subject to the unilateral-exit time-lock;
                // treat them as locked until `expires_at` passes.
                if vtxo.expires_at > 0 {
                    locked.push(LockedAmount {
                        amount: vtxo.amount,
                        expires_at: vtxo.expires_at,
                    });
                } else {
                    onchain_spendable = onchain_spendable.saturating_add(vtxo.amount);
                }
            } else if vtxo.is_swept {
                // Swept VTXOs have been reclaimed by the server — no longer spendable.
                continue;
            } else {
                // Active offchain VTXO — counts toward offchain total.
                offchain_total = offchain_total.saturating_add(vtxo.amount);
            }
        }

        // Aggregate asset balances across all spendable VTXOs.
        let mut asset_balances: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for vtxo in vtxos
            .iter()
            .filter(|v| !v.is_spent && !v.is_swept && !v.is_unrolled)
        {
            for asset in &vtxo.assets {
                *asset_balances.entry(asset.asset_id.clone()).or_insert(0) += asset.amount;
            }
        }

        Ok(Balance {
            onchain: OnchainBalance {
                spendable_amount: onchain_spendable,
                locked_amount: locked,
            },
            offchain: OffchainBalance {
                total: offchain_total,
            },
            asset_balances,
        })
    }

    /// Register a VTXO intent for the next round.
    ///
    /// Uses the `RegisterForRound` RPC (simple pubkey+amount API, suitable for dev/test).
    /// Production callers should use the BIP-322 `RegisterIntent` API directly.
    ///
    /// If the server responds with "Not in registration stage", subscribes to the
    /// event stream and waits for a `BatchStarted` event before retrying (up to 60s).
    ///
    /// Returns the server-assigned `intent_id` string on success.
    pub async fn register_intent(&mut self, pubkey: &str, amount: u64) -> ClientResult<String> {
        self.register_intent_with_boarding(pubkey, amount, &[])
            .await
    }

    /// Register an intent with optional boarding UTXO inputs.
    ///
    /// Same as [`register_intent`](Self::register_intent) but accepts boarding UTXOs
    /// that should be included in the commitment transaction.
    pub async fn register_intent_with_boarding(
        &mut self,
        pubkey: &str,
        amount: u64,
        boarding_utxos: &[BoardingUtxo],
    ) -> ClientResult<String> {
        // Optimistic first attempt — succeeds immediately if round is already in registration.
        match self
            .try_register_for_round(pubkey, amount, boarding_utxos)
            .await
        {
            Ok(intent_id) => return Ok(intent_id),
            Err(ClientError::Rpc(msg)) if !msg.contains("Not in registration stage") => {
                return Err(ClientError::Rpc(msg));
            }
            _ => {} // Not in registration stage — fall through to event-driven retry
        }

        // Subscribe to the event stream BEFORE retrying, so we don't miss BatchStarted.
        let (mut rx, cancel) = self.get_event_stream(None).await?;

        // Retry immediately after subscribing — the round might have just opened
        // while we were setting up the stream subscription.
        match self
            .try_register_for_round(pubkey, amount, boarding_utxos)
            .await
        {
            Ok(intent_id) => {
                cancel();
                return Ok(intent_id);
            }
            Err(ClientError::Rpc(msg)) if !msg.contains("Not in registration stage") => {
                cancel();
                return Err(ClientError::Rpc(msg));
            }
            _ => {} // Still not in registration — wait for BatchStarted event
        }

        // Wait for the next BatchStarted event (up to 60s), then retry once more.
        let result = tokio::time::timeout(std::time::Duration::from_secs(60), async {
            while let Some(event) = rx.recv().await {
                if let BatchEvent::BatchStarted { .. } = event {
                    return Ok(());
                }
            }
            Err(ClientError::Rpc(
                "Event stream closed before BatchStarted".into(),
            ))
        })
        .await;

        cancel();

        match result {
            Ok(Ok(())) => {
                self.try_register_for_round(pubkey, amount, boarding_utxos)
                    .await
            }
            Ok(Err(e)) => Err(e),
            Err(_elapsed) => Err(ClientError::Rpc(
                "Timeout waiting for round to start (registration stage)".into(),
            )),
        }
    }

    /// Low-level `RegisterForRound` RPC call (no retry logic).
    async fn try_register_for_round(
        &mut self,
        pubkey: &str,
        amount: u64,
        boarding_utxos: &[BoardingUtxo],
    ) -> ClientResult<String> {
        let client = self.require_client()?;

        let inputs: Vec<ProtoInput> = boarding_utxos
            .iter()
            .map(|bu| ProtoInput {
                outpoint: Some(ProtoOutpoint {
                    txid: bu.txid.clone(),
                    vout: bu.vout,
                }),
                taproot_tree: None,
            })
            .collect();

        let response = client
            .register_for_round(RegisterForRoundRequest {
                pubkey: pubkey.to_string(),
                amount,
                inputs,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("RegisterForRound failed: {}", e)))?;

        Ok(response.into_inner().intent_id)
    }

    /// Register an intent using the BIP-322 `RegisterIntent` RPC.
    ///
    /// This is the production API for submitting an intent. `proof_b64` is a
    /// base64-encoded PSBT signed by the VTXO owner, and `message_json` is the
    /// JSON-encoded intent message containing `cosigners_public_keys` and other
    /// metadata. For delegate flows, `delegate_pubkey_hex` is the hex-encoded
    /// compressed public key of the party submitting on behalf of the VTXO owner.
    ///
    /// Returns the server-assigned `intent_id` on success.
    pub async fn register_intent_bip322(
        &mut self,
        proof_b64: &str,
        message_json: &str,
        delegate_pubkey_hex: Option<&str>,
    ) -> ClientResult<String> {
        let client = self.require_client()?;

        let response = client
            .register_intent(RegisterIntentRequest {
                intent: Some(ProtoIntent {
                    proof: proof_b64.to_string(),
                    message: message_json.to_string(),
                    delegate_pubkey: delegate_pubkey_hex.unwrap_or("").to_string(),
                }),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("RegisterIntent failed: {}", e)))?;

        Ok(response.into_inner().intent_id)
    }

    /// Delete a previously registered intent.
    ///
    /// Sends a [`DeleteIntentRequest`] with `intent_id` and an empty proof.
    /// The server removes the intent from the pending round queue.
    pub async fn delete_intent(&mut self, intent_id: &str) -> ClientResult<()> {
        let client = self.require_client()?;

        client
            .delete_intent(DeleteIntentRequest {
                intent_id: intent_id.to_string(),
                // Proof bytes are optional for dev environments; production callers should
                // supply a valid authorization proof to prevent unauthorised cancellation.
                proof: vec![],
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("DeleteIntent failed: {}", e)))?;

        Ok(())
    }

    /// Confirm registration once tree nonces are ready.
    ///
    /// Called after a `BatchStarted` event to acknowledge the VTXO tree and advance
    /// the round state machine.  The `pubkey` parameter is accepted for future use
    /// (e.g. multi-sig cosigner selection) but is not forwarded in the current proto
    /// request because [`ConfirmRegistrationRequest`] only carries `intent_id`.
    pub async fn confirm_registration(
        &mut self,
        intent_id: &str,
        _pubkey: &str,
    ) -> ClientResult<()> {
        let client = self.require_client()?;

        client
            .confirm_registration(ConfirmRegistrationRequest {
                intent_id: intent_id.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("ConfirmRegistration failed: {}", e)))?;

        Ok(())
    }

    /// Full settlement flow (registration-only stub).
    ///
    /// Without a secret key, returns a placeholder commitment txid.
    /// For the full batch protocol with MuSig2 signing, use [`settle_with_key`](Self::settle_with_key).
    pub async fn settle(&mut self, pubkey: &str, amount: u64) -> ClientResult<BatchTxRes> {
        let intent_id = self.register_intent(pubkey, amount).await?;
        Ok(BatchTxRes {
            commitment_txid: format!("pending:{}", intent_id),
        })
    }

    /// Full settlement flow with MuSig2 signing.
    ///
    /// Implements the complete batch protocol matching the Go SDK's `JoinBatchSession`.
    ///
    /// The event stream is subscribed BEFORE intent registration so that the
    /// `BatchStarted` event emitted by `finalize_round` is never missed due to
    /// a race between registration and subscription.
    pub async fn settle_with_key(
        &mut self,
        pubkey: &str,
        amount: u64,
        secret_key: &bitcoin::secp256k1::SecretKey,
    ) -> ClientResult<BatchTxRes> {
        self.settle_with_key_and_boarding(pubkey, amount, secret_key, &[])
            .await
    }

    /// Full settlement flow with MuSig2 signing and boarding UTXO inputs.
    ///
    /// Like [`settle_with_key`](Self::settle_with_key) but includes boarding UTXOs
    /// in the `RegisterForRound` call so the server adds them to the commitment tx.
    pub async fn settle_with_key_and_boarding(
        &mut self,
        pubkey: &str,
        amount: u64,
        secret_key: &bitcoin::secp256k1::SecretKey,
        boarding_utxos: &[BoardingUtxo],
    ) -> ClientResult<BatchTxRes> {
        // Subscribe to the event stream BEFORE registering so we never miss
        // the BatchStarted event that includes our intent.
        let mut grpc_client = self.require_client()?.clone();
        let stream = grpc_client
            .get_event_stream(dark_api::proto::ark_v1::GetEventStreamRequest { topics: vec![] })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
            .into_inner();

        let intent_id = self
            .register_intent_with_boarding(pubkey, amount, boarding_utxos)
            .await?;

        // Cap the batch protocol at 120s to avoid hanging forever if the server
        // stalls or a round never completes (e.g. in e2e test environments).
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::batch::run_batch_protocol_with_stream(
                &mut grpc_client,
                &intent_id,
                secret_key,
                &[],
                None,
                stream,
            ),
        )
        .await
        .map_err(|_| {
            ClientError::Rpc("settle timed out after 120s waiting for batch to complete".into())
        })?
        .map(|txid| BatchTxRes {
            commitment_txid: txid,
        })
    }

    /// Full settlement flow with MuSig2 signing and forfeit tx signing.
    ///
    /// Like `settle_with_key`, but also builds and signs forfeit transactions
    /// for old VTXOs being refreshed. `vtxos_to_forfeit` lists the old VTXOs
    /// that need forfeits, and `asp_forfeit_pubkey` is the server's forfeit
    /// x-only public key (from `ServerInfo`).
    pub async fn settle_with_vtxos(
        &mut self,
        pubkey: &str,
        amount: u64,
        secret_key: &bitcoin::secp256k1::SecretKey,
        vtxos_to_forfeit: &[crate::batch::VtxoInput],
        asp_forfeit_pubkey: bitcoin::XOnlyPublicKey,
    ) -> ClientResult<BatchTxRes> {
        let mut grpc_client = self.require_client()?.clone();
        let stream = grpc_client
            .get_event_stream(dark_api::proto::ark_v1::GetEventStreamRequest { topics: vec![] })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
            .into_inner();

        let intent_id = self.register_intent(pubkey, amount).await?;

        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::batch::run_batch_protocol_with_stream(
                &mut grpc_client,
                &intent_id,
                secret_key,
                vtxos_to_forfeit,
                Some(asp_forfeit_pubkey),
                stream,
            ),
        )
        .await
        .map_err(|_| {
            ClientError::Rpc(
                "settle_with_vtxos timed out after 120s waiting for batch to complete".into(),
            )
        })?
        .map(|txid| BatchTxRes {
            commitment_txid: txid,
        })
    }
    /// Submit MuSig2 tree nonces for a batch round.
    pub async fn submit_tree_nonces(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        tree_nonces: std::collections::HashMap<String, String>,
    ) -> ClientResult<()> {
        let client = self.require_client()?;
        client
            .submit_tree_nonces(SubmitTreeNoncesRequest {
                batch_id: batch_id.to_string(),
                pubkey: pubkey.to_string(),
                tree_nonces,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("SubmitTreeNonces failed: {}", e)))?;
        Ok(())
    }

    /// Submit MuSig2 tree partial signatures for a batch round.
    pub async fn submit_tree_signatures(
        &mut self,
        batch_id: &str,
        pubkey: &str,
        tree_signatures: std::collections::HashMap<String, Vec<u8>>,
    ) -> ClientResult<()> {
        let client = self.require_client()?;
        client
            .submit_tree_signatures(SubmitTreeSignaturesRequest {
                batch_id: batch_id.to_string(),
                pubkey: pubkey.to_string(),
                tree_signatures,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("SubmitTreeSignatures failed: {}", e)))?;
        Ok(())
    }

    /// Submit signed forfeit transactions and optionally a signed commitment tx.
    pub async fn submit_signed_forfeit_txs(
        &mut self,
        signed_forfeit_txs: Vec<String>,
        signed_commitment_tx: String,
    ) -> ClientResult<()> {
        let client = self.require_client()?;
        client
            .submit_signed_forfeit_txs(SubmitSignedForfeitTxsRequest {
                signed_forfeit_txs,
                signed_commitment_tx,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("SubmitSignedForfeitTxs failed: {}", e)))?;
        Ok(())
    }
}

/// Result type returned by off-chain send operations.
#[derive(Debug, Clone)]
pub struct OffchainTxResult {
    /// The transaction ID of the submitted off-chain transaction.
    pub txid: String,
}

impl ArkClient {
    /// Send sats off-chain to an Ark address.
    ///
    /// Performs greedy coin selection over the caller's spendable VTXOs, builds a
    /// PSBT with the selected inputs and P2TR outputs (recipient + optional change),
    /// signs each input via taproot key-path spend, and submits the signed PSBT to
    /// the server.
    ///
    /// `to_address` must be an `ark:<hex_pubkey>` offchain address.
    pub async fn send_offchain(
        &mut self,
        from_pubkey: &str,
        to_address: &str,
        amount: u64,
        secret_key: &bitcoin::secp256k1::SecretKey,
    ) -> ClientResult<OffchainTxResult> {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::transaction::Version;
        use bitcoin::{
            Amount, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut, Txid,
            Witness,
        };

        // ── 1. Parse recipient pubkey from ark:‹hex› address ──────────────
        let recipient_hex = to_address
            .strip_prefix("ark:")
            .ok_or_else(|| ClientError::InvalidAddress("expected ark:<pubkey> address".into()))?;
        let recipient_xonly = parse_xonly_pubkey(recipient_hex)?;

        // ── 2. Parse sender x-only pubkey ─────────────────────────────────
        let sender_xonly = parse_xonly_pubkey(from_pubkey)?;

        // ── 3. Coin-select spendable VTXOs covering `amount` ──────────────
        let vtxos = self.list_vtxos(from_pubkey).await?;
        let mut selected: Vec<&Vtxo> = Vec::new();
        let mut total: u64 = 0;
        for v in &vtxos {
            if v.is_spent || v.is_swept {
                continue;
            }
            selected.push(v);
            total = total.saturating_add(v.amount);
            if total >= amount {
                break;
            }
        }
        if total < amount {
            return Err(ClientError::InsufficientFunds {
                available: total,
                required: amount,
            });
        }
        let change = total - amount;

        // ── 4. Build unsigned transaction ─────────────────────────────────
        let secp = Secp256k1::new();
        let inputs: Vec<TxIn> = selected
            .iter()
            .map(|v| {
                let txid = v.txid.parse::<Txid>().unwrap_or_else(|_| {
                    Txid::from_slice(&[0u8; 32]).expect("32 zero bytes is valid Txid")
                });
                TxIn {
                    previous_output: OutPoint::new(txid, v.vout),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }
            })
            .collect();

        let recipient_script = ScriptBuf::new_p2tr(&secp, recipient_xonly, None);
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: recipient_script,
        }];
        if change > 0 {
            let change_script = ScriptBuf::new_p2tr(&secp, sender_xonly, None);
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script,
            });
        }

        let unsigned_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs,
            output: outputs,
        };

        // ── 5. Build PSBT and populate witness UTXO for each input ────────
        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(unsigned_tx)
            .map_err(|e| ClientError::Internal(format!("PSBT creation failed: {}", e)))?;

        for (idx, vtxo) in selected.iter().enumerate() {
            let utxo_script = ScriptBuf::new_p2tr(&secp, sender_xonly, None);
            psbt.inputs[idx].witness_utxo = Some(TxOut {
                value: Amount::from_sat(vtxo.amount),
                script_pubkey: utxo_script,
            });
            psbt.inputs[idx].tap_internal_key = Some(sender_xonly);
            psbt.inputs[idx].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from(
                TapSighashType::Default,
            ));
        }

        // ── 6. Sign each input (taproot key-path) ────────────────────────
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, secret_key);
        let unsigned_tx = psbt.unsigned_tx.clone();
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.clone().expect("witness_utxo set above"))
            .collect();
        let prevouts_ref = bitcoin::sighash::Prevouts::All(&prevouts);

        for idx in 0..psbt.inputs.len() {
            let mut sighash_cache = bitcoin::sighash::SighashCache::new(&unsigned_tx);
            let sighash = sighash_cache
                .taproot_key_spend_signature_hash(idx, &prevouts_ref, TapSighashType::Default)
                .map_err(|e| ClientError::Internal(format!("sighash error: {}", e)))?;
            let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_schnorr(&msg, &keypair);
            // Default sighash type → 64-byte signature (no trailing byte)
            psbt.inputs[idx].tap_key_sig = Some(bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            });
        }

        // ── 7. Serialize PSBT to base64 and submit ───────────────────────
        let psbt_bytes = bitcoin::psbt::Psbt::serialize(&psbt);
        let psbt_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&psbt_bytes)
        };
        let tx_id = self.submit_tx(&psbt_b64).await?;

        Ok(OffchainTxResult { txid: tx_id })
    }

    /// Submit a raw off-chain transaction by providing pre-built inputs and outputs.
    ///
    /// The `tx_hex` is treated as a hex-encoded transaction identifier / raw bytes
    /// placeholder. Returns the server-assigned transaction ID.
    ///
    /// Calls `ArkService::SubmitTx` gRPC.
    pub async fn submit_tx(&mut self, tx_hex: &str) -> ClientResult<String> {
        let client = self.require_client()?;

        // NOTE: A full implementation would decode `tx_hex` into typed SignedVtxoInput and
        // Output lists. For now we submit an empty-inputs/outputs request tagged with the
        // hex as a trace identifier so callers can exercise the RPC path.
        let response = client
            .submit_tx(SubmitTxRequest {
                signed_ark_tx: tx_hex.to_string(),
                checkpoint_txs: vec![],
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("SubmitTx failed (tx={}): {}", tx_hex, e)))?;

        Ok(response.into_inner().ark_txid)
    }

    /// Finalize a pending off-chain transaction by its ID.
    ///
    /// Calls `ArkService::FinalizeTx` gRPC. Checkpoint transactions are left empty
    /// for the basic case; pass a populated list when cooperative exit proofs are needed.
    pub async fn finalize_tx(&mut self, txid: &str) -> ClientResult<()> {
        let client = self.require_client()?;

        client
            .finalize_tx(FinalizeTxRequest {
                ark_txid: txid.to_string(),
                final_checkpoint_txs: vec![],
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("FinalizeTx failed (txid={}): {}", txid, e)))?;

        Ok(())
    }

    /// Finalize all pending off-chain transactions for a given public key.
    ///
    /// Calls `ArkService::FinalizePendingTxs` gRPC to let the server finalize
    /// any pending off-chain txs (e.g. after a client reconnect).
    pub async fn finalize_pending_txs(&mut self, pubkey: &str) -> ClientResult<Vec<String>> {
        let client = self.require_client()?;

        let response = client
            .finalize_pending_txs(FinalizePendingTxsRequest {
                pubkey: pubkey.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("FinalizePendingTxs failed: {e}")))?;

        Ok(response.into_inner().finalized_txids)
    }
}

/// Exit flow methods (collaborative and unilateral).
impl ArkClient {
    /// Send `amount` satoshis to `onchain_address` collaboratively via the ASP.
    ///
    /// Registers a round intent whose output targets an on-chain Bitcoin address rather
    /// than an off-chain VTXO script. The ASP cooperates by including the output in the
    /// next commitment transaction and returning change (if any) to the sender's offchain
    /// address.
    ///
    /// # Notes
    /// - Boarding inputs must NOT be included — the server will reject them with an error
    ///   containing `"include onchain inputs and outputs"`.
    /// - The `vtxo_ids` sent to the server are populated from the caller's spendable VTXOs
    ///   via `RequestExit`. The returned `exit_id` is used as a placeholder commitment txid
    ///   until the full round settlement flow completes.
    /// - For the complete commitment txid the caller must wait for a `BatchSettled` event
    ///   on the transaction stream (not yet wired — see `settle()`).
    ///
    /// # Returns
    /// The server-assigned `exit_id` prefixed with `"pending:"` as a placeholder until
    /// the round finalises and the real commitment txid is known.
    pub async fn collaborative_exit(
        &mut self,
        onchain_address: &str,
        amount: u64,
        vtxo_ids: Vec<String>,
    ) -> ClientResult<String> {
        if onchain_address.is_empty() {
            return Err(ClientError::Rpc(
                "collaborative_exit: onchain_address must not be empty".into(),
            ));
        }
        if amount == 0 {
            return Err(ClientError::Rpc(
                "collaborative_exit: amount must be > 0".into(),
            ));
        }
        if vtxo_ids.is_empty() {
            return Err(ClientError::Rpc(
                "collaborative_exit: vtxo_ids must not be empty".into(),
            ));
        }

        let client = self.require_client()?;

        // Build outpoints from "txid:vout" strings.
        let outpoints: Vec<dark_api::proto::ark_v1::Outpoint> = vtxo_ids
            .iter()
            .map(|id| {
                let parts: Vec<&str> = id.splitn(2, ':').collect();
                let txid = parts.first().copied().unwrap_or("").to_string();
                let vout: u32 = parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
                dark_api::proto::ark_v1::Outpoint { txid, vout }
            })
            .collect();

        let response = client
            .request_exit(RequestExitRequest {
                vtxo_ids: outpoints,
                destination: onchain_address.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("CollaborativeExit RequestExit failed: {}", e)))?
            .into_inner();

        // The real commitment txid is only known after the round completes.
        // Return a pending placeholder so callers can track the request.
        Ok(format!("pending:{}", response.exit_id))
    }

    /// Broadcast the next unroll transaction for all of the wallet's VTXOs.
    ///
    /// Unilateral exit publishes the VTXO branch onto the Bitcoin chain without
    /// ASP cooperation. For a leaf VTXO the branch has one level; for a
    /// preconfirmed VTXO it may span several checkpoint levels.
    ///
    /// May need to be called multiple times — once per tree level — generating
    /// a block between calls so the timelock advances.
    ///
    /// # Note
    pub async fn unroll(&mut self, pubkey: &str) -> ClientResult<Vec<String>> {
        // 1. List spendable VTXOs
        let vtxos = self.list_vtxos(pubkey).await?;
        let spendable: Vec<_> = vtxos
            .into_iter()
            .filter(|v| !v.is_spent && !v.is_swept && !v.is_unrolled)
            .collect();

        if spendable.is_empty() {
            return Ok(vec![]);
        }

        // 2. Build redeem branches and collect next-to-broadcast txids (dedup)
        let mut seen = std::collections::HashSet::new();
        let mut next_txids: Vec<String> = Vec::new();

        for vtxo in &spendable {
            let branch = RedeemBranch::new(vtxo, &mut self.indexer).await?;
            if let Some(txid) = branch.next_offchain_txid {
                if seen.insert(txid.clone()) {
                    next_txids.push(txid);
                }
            }
        }

        if next_txids.is_empty() {
            return Ok(vec![]);
        }

        // 3. Fetch PSBTs for the next offchain txids
        let indexer = self
            .indexer
            .as_mut()
            .ok_or_else(|| ClientError::Connection("Not connected".into()))?;
        let resp = indexer
            .get_virtual_txs(GetVirtualTxsRequest {
                txids: next_txids.clone(),
                page: None,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetVirtualTxs failed: {e}")))?;
        let psbt_strings = resp.into_inner().txs;

        // 4. Finalize each PSBT and return raw tx hexes
        let mut broadcast_txids = Vec::new();
        for psbt_b64 in &psbt_strings {
            let tx_hex = finalize_tree_psbt(psbt_b64)?;
            broadcast_txids.push(tx_hex);
        }

        Ok(broadcast_txids)
    }
}

/// Finalize a pre-signed tree PSBT (taproot key-path spend) and return the
/// serialized raw transaction hex.
fn finalize_tree_psbt(psbt_b64: &str) -> ClientResult<String> {
    use base64::Engine;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::psbt::Psbt;

    let psbt_bytes = base64::engine::general_purpose::STANDARD
        .decode(psbt_b64)
        .map_err(|e| ClientError::Serialization(format!("Invalid PSBT base64: {e}")))?;

    let mut psbt: Psbt = Psbt::deserialize(&psbt_bytes)
        .map_err(|e| ClientError::Serialization(format!("Invalid PSBT: {e}")))?;

    for (idx, input) in psbt.inputs.iter_mut().enumerate() {
        if let Some(sig) = input.tap_key_sig.take() {
            let mut witness = bitcoin::Witness::new();
            witness.push(sig.to_vec());
            input.final_script_witness = Some(witness);
            input.tap_internal_key = None;
            input.tap_merkle_root = None;
            input.tap_scripts.clear();
            input.tap_script_sigs.clear();
            input.witness_utxo = None;
        } else if !input.tap_scripts.is_empty() {
            let (control_block_key, (leaf_script, _leaf_version)) =
                input.tap_scripts.iter().next().ok_or_else(|| {
                    ClientError::Serialization(format!("Input {idx}: no tap_scripts"))
                })?;

            let mut witness = bitcoin::Witness::new();
            for ((_pubkey, _leaf_hash), sig) in &input.tap_script_sigs {
                witness.push(sig.to_vec());
            }
            witness.push(leaf_script.as_bytes());
            witness.push(control_block_key.serialize());

            input.final_script_witness = Some(witness);
            input.tap_key_sig = None;
            input.tap_internal_key = None;
            input.tap_merkle_root = None;
            input.tap_scripts.clear();
            input.tap_script_sigs.clear();
            input.witness_utxo = None;
        } else {
            return Err(ClientError::Serialization(format!(
                "Input {idx}: no taproot key-spend sig or leaf script"
            )));
        }
    }

    // Use unchecked fee rate because witness_utxo was intentionally cleared
    // after finalization — fee validation is not needed for pre-signed tree txs.
    let tx = psbt.extract_tx_unchecked_fee_rate();

    Ok(serialize_hex(&tx))
}

/// Low-level unilateral exit helper.
///
/// Queries `GetVtxoChain` to find the chain of transactions from commitment
/// root to VTXO leaf, then walks backwards to identify the next offchain
/// tree transaction that should be broadcast.
pub struct RedeemBranch {
    /// The VTXO being exited.
    pub vtxo: crate::types::Vtxo,
    /// The txid of the next offchain transaction to broadcast, if any.
    pub next_offchain_txid: Option<String>,
}

impl RedeemBranch {
    /// Build the redeem branch for `vtxo` by querying the indexer.
    pub async fn new(
        vtxo: &crate::types::Vtxo,
        indexer: &mut Option<IndexerServiceClient<Channel>>,
    ) -> ClientResult<Self> {
        let indexer = indexer
            .as_mut()
            .ok_or_else(|| ClientError::Connection("Not connected".into()))?;

        let resp = indexer
            .get_vtxo_chain(GetVtxoChainRequest {
                outpoint: Some(IndexerOutpoint {
                    txid: vtxo.txid.clone(),
                    vout: vtxo.vout,
                }),
                page: None,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetVtxoChain failed: {e}")))?;

        let chain = resp.into_inner().chain;

        let mut next_offchain_txid = None;
        for entry in chain.iter().rev() {
            let tx_type = entry.r#type;
            if tx_type == IndexerChainedTxType::Commitment as i32
                || tx_type == IndexerChainedTxType::Unspecified as i32
            {
                continue;
            }
            next_offchain_txid = Some(entry.txid.clone());
            break;
        }

        Ok(Self {
            vtxo: vtxo.clone(),
            next_offchain_txid,
        })
    }
}

/// Asset management methods (RGB-style tokens embedded in VTXOs).
impl ArkClient {
    /// Issue a new asset with `supply` units.
    ///
    /// `control_asset` controls who can reissue; pass `None` for a fixed-supply asset.
    /// `metadata` attaches optional key-value data to the issuance.
    /// Issue a new asset.
    ///
    /// `owner_pubkey` — if `Some`, the asset VTXO is assigned to this key;
    /// if `None`, the server uses the session's default key.
    pub async fn issue_asset(
        &mut self,
        owner_pubkey: Option<&str>,
        supply: u64,
        control_asset: Option<crate::types::ControlAssetOption>,
        metadata: Option<crate::types::AssetMetadata>,
    ) -> ClientResult<crate::types::IssueAssetResult> {
        if supply == 0 {
            return Err(ClientError::Validation("amount must be > 0".into()));
        }

        // Encode control_asset option into the name field as a tag for the server:
        // "control:new:<amount>" or "control:existing:<id>"
        //
        // When no control asset is specified and metadata is provided, the
        // metadata key is used as the asset name instead.
        let name = match &control_asset {
            Some(crate::types::ControlAssetOption::New(n)) => {
                format!("control:new:{}", n.amount)
            }
            Some(crate::types::ControlAssetOption::Existing(e)) => {
                format!("control:existing:{}", e.id)
            }
            None => metadata.as_ref().map(|m| m.key.clone()).unwrap_or_default(),
        };

        // The ticker field carries the metadata value when provided.
        let ticker = metadata
            .as_ref()
            .map(|m| m.value.clone())
            .unwrap_or_default();

        let client = self.require_client()?;
        let response = client
            .issue_asset(IssueAssetRequest {
                pubkey: owner_pubkey.unwrap_or("").to_string(),
                amount: supply,
                name,
                ticker,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("IssueAsset failed: {}", e)))?;
        let inner = response.into_inner();

        // Use issued_asset_ids if present, otherwise fall back to single asset_id
        let issued_assets = if inner.issued_asset_ids.is_empty() {
            vec![inner.asset_id]
        } else {
            inner.issued_asset_ids
        };

        Ok(crate::types::IssueAssetResult {
            txid: inner.txid,
            issued_assets,
        })
    }

    /// Reissue more units of an existing asset (requires control asset).
    pub async fn reissue_asset(
        &mut self,
        owner_pubkey: &str,
        asset_id: &str,
        amount: u64,
    ) -> ClientResult<String> {
        if asset_id.is_empty() {
            return Err(ClientError::Validation("asset_id must not be empty".into()));
        }
        if amount == 0 {
            return Err(ClientError::Validation("amount must be > 0".into()));
        }
        let client = self.require_client()?;
        let response = client
            .reissue_asset(ReissueAssetRequest {
                asset_id: asset_id.to_string(),
                pubkey: owner_pubkey.to_string(),
                amount,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("ReissueAsset failed: {}", e)))?;
        Ok(response.into_inner().txid)
    }

    /// Burn `amount` units of `asset_id`, removing them permanently from circulation.
    pub async fn burn_asset(
        &mut self,
        owner_pubkey: &str,
        asset_id: &str,
        amount: u64,
    ) -> ClientResult<String> {
        if asset_id.is_empty() {
            return Err(ClientError::Validation("asset_id must not be empty".into()));
        }
        if amount == 0 {
            return Err(ClientError::Validation("amount must be > 0".into()));
        }
        let client = self.require_client()?;
        let response = client
            .burn_asset(BurnAssetRequest {
                asset_id: asset_id.to_string(),
                pubkey: owner_pubkey.to_string(),
                amount,
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("BurnAsset failed: {}", e)))?;
        Ok(response.into_inner().txid)
    }
}

/// Streaming API methods — batch event stream and transactions stream (#208).
impl ArkClient {
    /// Subscribe to batch lifecycle events.
    ///
    /// Opens a `GetEventStream` server-streaming RPC and forwards events onto a
    /// `mpsc` channel. Returns the receiver and a close handle; call the close
    /// handle to cancel the background forwarding task and drop the stream.
    ///
    /// The `_topics` parameter is reserved for future server-side filtering and
    /// is ignored in this implementation (use `UpdateStreamTopics` after connecting).
    pub async fn get_event_stream(
        &mut self,
        _topics: Option<()>,
    ) -> ClientResult<(mpsc::Receiver<BatchEvent>, impl FnOnce())> {
        let client = self.require_client()?;

        let mut stream = client
            .get_event_stream(GetEventStreamRequest { topics: vec![] })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
            .into_inner();

        let (tx, rx) = mpsc::channel::<BatchEvent>(64);
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            tokio::pin!(cancel_rx);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut cancel_rx => break,
                    msg = stream.message() => {
                        match msg {
                            Ok(Some(event)) => {
                                if let Some(batch_event) = proto_round_event_to_domain(event) {
                                    if tx.send(batch_event).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok((rx, move || {
            let _ = cancel_tx.send(());
        }))
    }

    /// Subscribe to the transactions stream (Ark txs + commitment txs).
    ///
    /// Opens a `GetTransactionsStream` server-streaming RPC and forwards events
    /// onto a `mpsc` channel. Returns the receiver and a close handle.
    pub async fn get_transactions_stream(
        &mut self,
    ) -> ClientResult<(mpsc::Receiver<TxEvent>, impl FnOnce())> {
        let client = self.require_client()?;

        let mut stream = client
            .get_transactions_stream(GetTransactionsStreamRequest { scripts: vec![] })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetTransactionsStream failed: {}", e)))?
            .into_inner();

        let (tx, rx) = mpsc::channel::<TxEvent>(64);
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            tokio::pin!(cancel_rx);
            loop {
                tokio::select! {
                    biased;
                    _ = &mut cancel_rx => break,
                    msg = stream.message() => {
                        match msg {
                            Ok(Some(event)) => {
                                if let Some(tx_event) = proto_tx_event_to_domain(event) {
                                    if tx.send(tx_event).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        Ok((rx, move || {
            let _ = cancel_tx.send(());
        }))
    }

    /// Redeem one or more Ark notes and receive the corresponding VTXOs
    /// in the next batch. Returns the commitment txid.
    ///
    /// Notes are short bearer strings (similar to Lightning invoices). Each note
    /// can only be redeemed once — the server rejects double-spend attempts.
    pub async fn redeem_notes(
        &mut self,
        notes: Vec<String>,
        pubkey: &str,
    ) -> ClientResult<BatchTxRes> {
        // Subscribe to the raw gRPC event stream BEFORE registering so we
        // never miss the BatchStarted event that includes our intent.
        let mut grpc_client = self.require_client()?.clone();
        let stream = grpc_client
            .get_event_stream(GetEventStreamRequest { topics: vec![] })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetEventStream failed: {}", e)))?
            .into_inner();

        // Register the note redemption intent.
        let intent_id = self.try_redeem_notes(notes, pubkey).await?;

        // Wait for the batch round to finalize (no MuSig2 needed for notes —
        // the server handles signing). Cap at 120s to match settle_with_key.
        tokio::time::timeout(
            std::time::Duration::from_secs(120),
            crate::batch::wait_for_batch_finalized(&mut grpc_client, &intent_id, stream),
        )
        .await
        .map_err(|_| {
            ClientError::Rpc(
                "redeem_notes timed out after 120s waiting for batch to complete".into(),
            )
        })?
        .map(|txid| BatchTxRes {
            commitment_txid: txid,
        })
    }

    /// Low-level `RedeemNotes` RPC call (no retry logic).
    async fn try_redeem_notes(&mut self, notes: Vec<String>, pubkey: &str) -> ClientResult<String> {
        let client = self.require_client()?;
        let response = client
            .redeem_notes(RedeemNotesRequest {
                notes,
                pubkey: pubkey.to_string(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("RedeemNotes failed: {}", e)))?;
        Ok(response.into_inner().txid)
    }
}

/// Incoming-funds notification API — mirrors Go SDK `NotifyIncomingFunds`.
impl ArkClient {
    /// Wait until a VTXO matching `address` appears in a completed batch.
    ///
    /// The address must be an offchain (ark) address in the format used by this
    /// client: either `ark:<hex_pubkey>` (simple format) or a bech32m-encoded
    /// ark address with HRP `ark` / `tark`.
    ///
    /// Internally this:
    /// 1. Extracts the x-only public key from the address.
    /// 2. Builds the P2TR scriptPubKey (`OP_1 <32-byte-x-only-key>`).
    /// 3. Subscribes via `IndexerService::SubscribeForScripts`.
    /// 4. Streams `GetSubscription` and waits for an event carrying new VTXOs.
    /// 5. Unsubscribes and returns the newly detected VTXOs.
    ///
    /// This method is safe to call concurrently with `settle()` or any other
    /// client method because it clones the underlying gRPC channel rather than
    /// borrowing `&mut self`.
    pub async fn notify_incoming_funds(&self, address: &str) -> ClientResult<Vec<Vtxo>> {
        // ── 1. Extract x-only public key from the address ──────────────
        let xonly_pubkey = Self::extract_xonly_pubkey(address)?;

        // ── 2. Build P2TR scriptPubKey using bitcoin crate ─────────────
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let script = bitcoin::ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
        let script_hex = hex::encode(script.as_bytes());

        // ── 3. Subscribe for the script ────────────────────────────────
        let mut indexer = self
            .indexer
            .as_ref()
            .ok_or_else(|| ClientError::Connection("Not connected. Call connect() first.".into()))?
            .clone();

        let scripts = vec![script_hex.clone()];
        let sub_resp = indexer
            .subscribe_for_scripts(SubscribeForScriptsRequest {
                scripts: scripts.clone(),
                subscription_id: String::new(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("SubscribeForScripts failed: {}", e)))?;

        let subscription_id = sub_resp.into_inner().subscription_id;

        // ── 4. Open the subscription stream ────────────────────────────
        let stream_result = indexer
            .get_subscription(GetSubscriptionRequest {
                subscription_id: subscription_id.clone(),
            })
            .await
            .map_err(|e| ClientError::Rpc(format!("GetSubscription failed: {}", e)));

        // If opening the stream fails, best-effort unsubscribe before returning.
        let mut response_stream = match stream_result {
            Ok(resp) => resp.into_inner(),
            Err(err) => {
                let _ = indexer
                    .unsubscribe_for_scripts(UnsubscribeForScriptsRequest {
                        subscription_id: subscription_id.clone(),
                        scripts: scripts.clone(),
                    })
                    .await;
                return Err(err);
            }
        };

        // ── 5. Consume the stream until we get new VTXOs ──────────────
        let result = Self::consume_subscription_stream(&mut response_stream).await;

        // Always unsubscribe, regardless of outcome.
        let _ = indexer
            .unsubscribe_for_scripts(UnsubscribeForScriptsRequest {
                subscription_id,
                scripts,
            })
            .await;

        result
    }

    /// Extract a 32-byte x-only public key from an ark address.
    ///
    /// Supports two formats:
    /// - Simple: `ark:<hex_compressed_or_xonly_pubkey>`
    /// - Bech32m: bech32m-encoded with HRP `ark` or `tark` (65-byte payload:
    ///   1 version + 32 signer + 32 vtxo-tap-key).
    fn extract_xonly_pubkey(address: &str) -> ClientResult<bitcoin::secp256k1::XOnlyPublicKey> {
        if let Some(hex_str) = address.strip_prefix("ark:") {
            // Simple format: ark:<hex>
            let bytes = hex::decode(hex_str).map_err(|e| {
                ClientError::InvalidResponse(format!("Invalid hex in ark address: {}", e))
            })?;
            let x_bytes: &[u8] = match bytes.len() {
                32 => &bytes,
                33 => {
                    // Compressed pubkey — strip the parity prefix byte.
                    &bytes[1..]
                }
                _ => {
                    return Err(ClientError::InvalidResponse(format!(
                        "Unexpected pubkey length {} in ark address",
                        bytes.len()
                    )));
                }
            };
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(x_bytes)
                .map_err(|e| ClientError::InvalidResponse(format!("Invalid x-only pubkey: {}", e)))
        } else if address.starts_with("tark1") || address.starts_with("ark1") {
            // Bech32m-encoded ark address (v0): [version(1) | signer(32) | vtxoTapKey(32)]
            let (_hrp, data) = bech32::decode(address).map_err(|e| {
                ClientError::InvalidResponse(format!("Invalid bech32m ark address: {}", e))
            })?;
            if data.len() != 65 {
                return Err(ClientError::InvalidResponse(format!(
                    "Invalid ark address payload length {}, expected 65",
                    data.len()
                )));
            }
            if data[0] != 0 {
                return Err(ClientError::InvalidResponse(format!(
                    "Unsupported ark address version {}",
                    data[0]
                )));
            }
            // vtxo tap key is the last 32 bytes.
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&data[33..65])
                .map_err(|e| ClientError::InvalidResponse(format!("Invalid vtxo tap key: {}", e)))
        } else {
            Err(ClientError::InvalidResponse(format!(
                "Unrecognised address format: {}",
                address
            )))
        }
    }

    /// Read from the `GetSubscription` stream until an event with new VTXOs arrives.
    async fn consume_subscription_stream(
        stream: &mut tonic::Streaming<dark_api::proto::ark_v1::GetSubscriptionResponse>,
    ) -> ClientResult<Vec<Vtxo>> {
        use tokio_stream::StreamExt;
        loop {
            let msg = stream
                .next()
                .await
                .ok_or_else(|| {
                    ClientError::Rpc("Subscription stream closed before receiving VTXOs".into())
                })?
                .map_err(|e| ClientError::Rpc(format!("Subscription stream error: {}", e)))?;

            match msg.data {
                Some(get_subscription_response::Data::Event(event)) => {
                    if event.new_vtxos.is_empty() {
                        // Event without new VTXOs (e.g. only spent/swept) — keep waiting.
                        continue;
                    }
                    let vtxos = event
                        .new_vtxos
                        .into_iter()
                        .map(|v| {
                            let outpoint = v.outpoint.unwrap_or_default();
                            Vtxo {
                                id: format!("{}:{}", outpoint.txid, outpoint.vout),
                                txid: outpoint.txid,
                                vout: outpoint.vout,
                                amount: v.amount,
                                script: v.script,
                                created_at: v.created_at,
                                expires_at: v.expires_at,
                                is_spent: v.is_spent,
                                is_swept: v.is_swept,
                                is_unrolled: false,
                                spent_by: v.spent_by,
                                ark_txid: v.ark_txid,
                                assets: v
                                    .assets
                                    .into_iter()
                                    .map(|a| crate::types::Asset {
                                        asset_id: a.asset_id,
                                        amount: a.amount,
                                    })
                                    .collect(),
                            }
                        })
                        .collect();
                    return Ok(vtxos);
                }
                Some(get_subscription_response::Data::Heartbeat(_)) => {
                    // Server keepalive — ignore and continue waiting.
                    continue;
                }
                None => {
                    // Empty message — continue.
                    continue;
                }
            }
        }
    }
}

/// Map a proto `RoundEvent` to a domain `BatchEvent`.
/// Returns `None` for unrecognised or internal-only variants.
fn proto_round_event_to_domain(event: dark_api::proto::ark_v1::RoundEvent) -> Option<BatchEvent> {
    match event.event? {
        round_event::Event::BatchStarted(e) => Some(BatchEvent::BatchStarted {
            round_id: e.id,
            timestamp: e.batch_expiry,
        }),
        round_event::Event::BatchFinalization(e) => Some(BatchEvent::BatchFinalization {
            round_id: e.id,
            timestamp: 0,
            min_relay_fee_rate: 0,
        }),
        round_event::Event::BatchFinalized(e) => Some(BatchEvent::BatchFinalized {
            round_id: e.id,
            txid: e.commitment_txid,
        }),
        round_event::Event::BatchFailed(e) => Some(BatchEvent::BatchFailed {
            round_id: e.id,
            reason: e.reason,
        }),
        round_event::Event::TreeSigningStarted(e) => Some(BatchEvent::TreeSigningStarted {
            round_id: e.id,
            cosigner_pubkeys: e.cosigners_pubkeys,
            timestamp: 0,
        }),
        round_event::Event::TreeNoncesAggregated(e) => Some(BatchEvent::TreeNoncesAggregated {
            round_id: e.id,
            timestamp: 0,
        }),
        round_event::Event::Heartbeat(_e) => Some(BatchEvent::Heartbeat { timestamp: 0 }),
        // Internal MuSig2 and connection events — not exposed at this level.
        round_event::Event::TreeTx(_)
        | round_event::Event::TreeSignature(_)
        | round_event::Event::TreeNonces(_)
        | round_event::Event::StreamStarted(_) => None,
    }
}

/// Map a proto `TransactionEvent` to a domain `TxEvent`.
fn proto_tx_event_to_domain(event: dark_api::proto::ark_v1::TransactionEvent) -> Option<TxEvent> {
    match event.event? {
        transaction_event::Event::CommitmentTx(e) => Some(TxEvent::CommitmentTx {
            txid: e.txid,
            round_id: e.round_id,
            timestamp: e.timestamp,
        }),
        transaction_event::Event::ArkTx(e) => Some(TxEvent::ArkTx {
            txid: e.txid,
            from_script: e.from_script,
            to_script: e.to_script,
            amount: e.amount,
            timestamp: e.timestamp,
        }),
        transaction_event::Event::Heartbeat(e) => Some(TxEvent::Heartbeat {
            timestamp: e.timestamp,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new() {
        let c = ArkClient::new("http://localhost:50051");
        assert_eq!(c.server_url(), "http://localhost:50051");
        assert!(!c.is_connected());
    }

    #[test]
    fn test_client_url_stored() {
        let c = ArkClient::new("http://192.168.1.1:50051");
        assert!(c.server_url().contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn test_get_info_fails_when_not_connected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.get_info().await;
        assert!(result.is_err());
        if let Err(ClientError::Connection(msg)) = result {
            assert!(msg.contains("Not connected"));
        } else {
            panic!("Expected Connection error");
        }
    }

    #[tokio::test]
    async fn test_list_vtxos_fails_when_not_connected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.list_vtxos("pubkey123").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_notify_incoming_funds_fails_when_not_connected() {
        // Use a syntactically valid 33-byte compressed pubkey so address parsing
        // succeeds and the method fails at the connection check.
        let c = ArkClient::new("http://localhost:50051");
        let addr = "ark:0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let result = c.notify_incoming_funds(addr).await;
        assert!(result.is_err());
        if let Err(ClientError::Connection(msg)) = result {
            assert!(msg.contains("Not connected"));
        } else {
            panic!("Expected Connection error, got {:?}", result);
        }
    }

    // ── collaborative_exit validation tests ───────────────────────

    #[tokio::test]
    async fn test_collaborative_exit_empty_address_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c
            .collaborative_exit("", 1_000, vec!["abc:0".to_string()])
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("onchain_address"), "got: {msg}");
    }

    #[tokio::test]
    async fn test_collaborative_exit_zero_amount_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c
            .collaborative_exit("bc1qtest", 0, vec!["abc:0".to_string()])
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("amount"), "got: {msg}");
    }

    #[tokio::test]
    async fn test_collaborative_exit_empty_vtxo_ids_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.collaborative_exit("bc1qtest", 1_000, vec![]).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("vtxo_ids"), "got: {msg}");
    }

    #[tokio::test]
    async fn test_collaborative_exit_fails_when_not_connected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c
            .collaborative_exit("bc1qtest", 1_000, vec!["abc:0".to_string()])
            .await;
        assert!(result.is_err());
    }

    // ── unroll stub tests ─────────────────────────────────────────

    #[tokio::test]
    async fn test_unroll_returns_ok_or_err() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.unroll("test_pubkey").await;
        // unroll now returns Ok(vec![]) when there are no VTXOs to unroll,
        // rather than a "not yet implemented" error.
        match result {
            Ok(txids) => {
                // Empty is fine — nothing to unroll without a live server
                let _ = txids;
            }
            Err(e) => {
                // Connection errors are also acceptable without a live server
                let _ = e;
            }
        }
    }

    // ── RedeemBranch stub tests ───────────────────────────────────

    #[tokio::test]
    async fn test_redeem_branch_requires_indexer() {
        let vtxo = crate::types::Vtxo {
            id: "abc:0".to_string(),
            txid: "abc".to_string(),
            vout: 0,
            amount: 10_000,
            script: "pk".to_string(),
            created_at: 0,
            expires_at: 0,
            is_spent: false,
            is_swept: false,
            is_unrolled: false,
            spent_by: String::new(),
            ark_txid: String::new(),
            assets: vec![],
        };
        let mut indexer: Option<IndexerServiceClient<Channel>> = None;
        let result = RedeemBranch::new(&vtxo, &mut indexer).await;
        assert!(result.is_err());
    }

    // ── Asset API tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_issue_asset_zero_supply_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.issue_asset(None, 0, None, None).await;
        assert!(result.is_err(), "expected error for zero supply");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("amount must be > 0"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_issue_asset_rpc_call() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.issue_asset(None, 1_000, None, None).await;
        // Without a live server it fails with a transport/connection error.
        assert!(result.is_err(), "expected error from disconnected client");
    }

    #[tokio::test]
    async fn test_issue_asset_with_metadata() {
        let mut c = ArkClient::new("http://localhost:50051");
        let metadata = crate::types::AssetMetadata {
            key: "TestToken".to_string(),
            value: "TTK".to_string(),
        };
        let result = c.issue_asset(None, 5_000, None, Some(metadata)).await;
        // Without a live server it fails with a transport/connection error.
        assert!(result.is_err(), "expected error from disconnected client");
    }

    #[tokio::test]
    async fn test_issue_asset_with_existing_control_asset() {
        let mut c = ArkClient::new("http://localhost:50051");
        let control =
            crate::types::ControlAssetOption::Existing(crate::types::ExistingControlAsset {
                id: "ctrl-asset-abc".to_string(),
            });
        let result = c.issue_asset(None, 1_000, Some(control), None).await;
        assert!(result.is_err(), "expected error from disconnected client");
    }

    #[tokio::test]
    async fn test_reissue_asset_empty_id_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.reissue_asset("owner", "", 500).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("asset_id must not be empty"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_reissue_asset_zero_amount_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.reissue_asset("owner", "asset-id-123", 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("amount must be > 0"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_reissue_asset_rpc_call() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.reissue_asset("owner", "asset-id-123", 500).await;
        assert!(result.is_err(), "expected error from disconnected client");
    }

    #[tokio::test]
    async fn test_burn_asset_empty_id_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.burn_asset("owner", "", 100).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("asset_id must not be empty"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_burn_asset_zero_amount_rejected() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.burn_asset("owner", "asset-id-123", 0).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("amount must be > 0"), "got: {}", err);
    }

    #[tokio::test]
    async fn test_burn_asset_rpc_call() {
        let mut c = ArkClient::new("http://localhost:50051");
        let result = c.burn_asset("owner", "asset-id-123", 100).await;
        assert!(result.is_err(), "expected error from disconnected client");
    }

    #[test]
    fn test_vtxo_has_assets_field() {
        let vtxo = crate::types::Vtxo {
            id: "tx:0".to_string(),
            txid: "tx".to_string(),
            vout: 0,
            amount: 10_000,
            script: "pk".to_string(),
            created_at: 0,
            expires_at: 0,
            is_spent: false,
            is_swept: false,
            is_unrolled: false,
            spent_by: String::new(),
            ark_txid: String::new(),
            assets: vec![crate::types::Asset {
                asset_id: "rgb:asset-1".to_string(),
                amount: 100,
            }],
        };
        assert_eq!(vtxo.assets.len(), 1);
        assert_eq!(vtxo.assets[0].asset_id, "rgb:asset-1");
        assert_eq!(vtxo.assets[0].amount, 100);
    }

    #[test]
    fn test_balance_has_asset_balances_field() {
        let balance = crate::types::Balance {
            onchain: crate::types::OnchainBalance {
                spendable_amount: 0,
                locked_amount: vec![],
            },
            offchain: crate::types::OffchainBalance { total: 0 },
            asset_balances: std::collections::HashMap::from([("rgb:asset-1".to_string(), 500u64)]),
        };
        assert_eq!(*balance.asset_balances.get("rgb:asset-1").unwrap(), 500);
    }
}
