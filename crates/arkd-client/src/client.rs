//! ArkClient — typed gRPC client for arkd-rs server.

use crate::error::{ClientError, ClientResult};
use crate::types::{
    Balance, BatchTxRes, BoardingAddress, LockedAmount, OffchainAddress, OffchainBalance,
    OnchainBalance, RoundInfo, RoundSummary, ServerInfo, Vtxo,
};
use arkd_api::proto::ark_v1::{
    ark_service_client::ArkServiceClient, output, transaction_event, ConfirmRegistrationRequest,
    DeleteIntentRequest, GetInfoRequest, GetRoundRequest, GetTransactionsStreamRequest,
    GetVtxosRequest, IntentDescriptor, ListRoundsRequest, Output, RegisterIntentRequest,
};
use tonic::transport::Channel;

/// Client for communicating with an arkd-rs server.
pub struct ArkClient {
    server_url: String,
    client: Option<ArkServiceClient<Channel>>,
}

impl ArkClient {
    /// Create a new client for `server_url` (e.g. `http://localhost:50051`).
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            client: None,
        }
    }

    /// Connect to the server. Call this before making RPC calls.
    pub async fn connect(&mut self) -> ClientResult<()> {
        let channel = Channel::from_shared(self.server_url.clone())
            .map_err(|e| ClientError::Connection(format!("Invalid URL: {}", e)))?
            .connect()
            .await
            .map_err(|e| ClientError::Connection(format!("Failed to connect: {}", e)))?;

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
                is_spent: true,
                is_swept: v.is_swept,
                is_unrolled: v.is_unrolled,
                spent_by: v.spent_by,
                ark_txid: v.ark_txid,
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
        //   2. Exit path: <user_pubkey> CHECKSEQUENCEVERIFY after unilateral_exit_delay blocks
        let coop_leaf = format!(
            "OP_CHECKSIG pubkey:{} AND pubkey:{}",
            pubkey, info.forfeit_pubkey
        );
        let exit_delay = info.unilateral_exit_delay;
        let exit_leaf = format!(
            "OP_CHECKSEQUENCEVERIFY {} OP_CHECKSIG pubkey:{}",
            exit_delay, pubkey
        );
        let boarding_address = BoardingAddress {
            address: format!("bc1p_boarding_{}", &pubkey[..pubkey.len().min(32)]),
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

        Ok(Balance {
            onchain: OnchainBalance {
                spendable_amount: onchain_spendable,
                locked_amount: locked,
            },
            offchain: OffchainBalance {
                total: offchain_total,
            },
        })
    }

    /// Subscribe to the transaction event stream and resolve when a VTXO arrives at `address`.
    ///
    /// This method opens a `GetTransactionsStream` gRPC server-streaming call and filters
    /// `ArkTxEvent` messages whose `to_script` matches `address`. It returns as soon as at
    /// least one matching VTXO is detected, or when `timeout_secs` elapses (if provided).
    ///
    /// **Note:** Only the *first* matching `ArkTxEvent` is captured; the loop breaks immediately
    /// after one match. If multiple VTXOs arrive simultaneously only the first is returned.
    ///
    /// # Parameters
    /// - `address`: The script / address string to watch for incoming funds.
    /// - `timeout_secs`: Optional wall-clock timeout. When `None` the call blocks until the
    ///   server closes the stream or the first matching event is received.
    ///
    /// # Returns
    /// A `Vec<Vtxo>` containing the first matching VTXO observed. Returns an empty `Vec` if the
    /// stream ends or the timeout fires before any matching event arrives.
    pub async fn notify_incoming_funds(
        &mut self,
        address: &str,
        timeout_secs: Option<u64>,
    ) -> ClientResult<Vec<Vtxo>> {
        let client = self.require_client()?;

        // Open the server-streaming call, filtering by the target script on the server side
        // when possible (the `scripts` field is optional; the server may ignore it and stream
        // all events, in which case we filter client-side below).
        let request = GetTransactionsStreamRequest {
            scripts: vec![address.to_string()],
        };

        let mut stream = client
            .get_transactions_stream(request)
            .await
            .map_err(|e| ClientError::Rpc(format!("GetTransactionsStream failed: {}", e)))?
            .into_inner();

        let address_owned = address.to_string();
        let mut matched: Vec<Vtxo> = Vec::new();

        // Helper closure that drives the stream-reading future.
        let read_stream = async {
            loop {
                match stream.message().await {
                    Ok(Some(event)) => {
                        if let Some(transaction_event::Event::ArkTx(ark_tx)) = event.event {
                            // Client-side filter: only keep events destined for our address.
                            if ark_tx.to_script == address_owned {
                                matched.push(Vtxo {
                                    // Ark tx events don't carry a traditional outpoint; use
                                    // the txid as the identifier until the stream provides one.
                                    id: ark_tx.txid.clone(),
                                    txid: ark_tx.txid.clone(),
                                    vout: 0,
                                    amount: ark_tx.amount,
                                    script: ark_tx.to_script.clone(),
                                    created_at: ark_tx.timestamp,
                                    expires_at: 0,
                                    is_spent: false,
                                    is_swept: false,
                                    is_unrolled: false,
                                    spent_by: String::new(),
                                    ark_txid: ark_tx.txid.clone(),
                                });
                                // Resolve as soon as we have at least one match.
                                break;
                            }
                            // Non-matching event — keep waiting.
                        }
                        // Heartbeat or CommitmentTx events are ignored; we keep listening.
                    }
                    Ok(None) => {
                        // Stream ended cleanly.
                        break;
                    }
                    Err(e) => {
                        return Err(ClientError::Rpc(format!("Transaction stream error: {}", e)));
                    }
                }
            }
            Ok(matched)
        };

        // Apply an optional timeout so callers (e.g. tests) never hang forever.
        // We distinguish the timeout case (Err(Elapsed)) from a real transport error so that
        // genuine RPC failures are still propagated to the caller.
        if let Some(secs) = timeout_secs {
            match tokio::time::timeout(std::time::Duration::from_secs(secs), read_stream).await {
                Ok(result) => result,
                Err(_elapsed) => Ok(Vec::new()),
            }
        } else {
            read_stream.await
        }
    }

    /// Register a VTXO intent for the next round.
    ///
    /// Builds a [`RegisterIntentRequest`] with a single output targeting `pubkey` (as a VTXO
    /// script) for `amount` satoshis and an empty proof descriptor (sufficient for local
    /// devnets; production callers should supply a real BIP-322 proof in the descriptor).
    ///
    /// Returns the server-assigned `intent_id` string on success.
    pub async fn register_intent(&mut self, pubkey: &str, amount: u64) -> ClientResult<String> {
        let client = self.require_client()?;

        let out = Output {
            amount,
            destination: Some(output::Destination::VtxoScript(pubkey.to_string())),
        };

        // An empty descriptor is accepted by the server for dev/test scenarios.
        // Production callers must populate `descriptor.intent` with a valid BIP-322 proof.
        let descriptor = IntentDescriptor {
            intent: None,
            boarding_inputs: vec![],
            cosigners_public_keys: vec![],
        };

        let response = client
            .register_intent(RegisterIntentRequest {
                outputs: vec![out],
                descriptor: Some(descriptor),
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

    /// Full settlement flow: register intent, wait for round, confirm, sign, submit forfeits.
    ///
    /// This is a **stub implementation**.  The complete flow requires:
    /// 1. `RegisterIntent` — register a VTXO output for the next round  ✅ done here
    /// 2. Wait for `BatchStarted` event on the transaction stream
    /// 3. `ConfirmRegistration` — acknowledge the VTXO tree
    /// 4. MuSig2 tree signing (`SubmitTreeNonces` / `SubmitTreeSignatures`)
    /// 5. `SubmitSignedForfeitTxs` — provide forfeit transaction signatures
    ///
    /// Steps 2-5 require a full MuSig2 signer and are deferred to a follow-up issue.
    ///
    /// # Returns
    /// A [`BatchTxRes`] with a placeholder `commitment_txid` derived from the `intent_id`.
    ///
    /// TODO: implement steps 2-5 once MuSig2 key-path signing is wired up.
    pub async fn settle(&mut self, pubkey: &str, amount: u64) -> ClientResult<BatchTxRes> {
        let intent_id = self.register_intent(pubkey, amount).await?;

        // TODO: subscribe to GetTransactionsStream and wait for a BatchStarted event,
        // then call confirm_registration, SubmitTreeNonces, SubmitTreeSignatures, and
        // SubmitSignedForfeitTxs to complete the full MuSig2 settlement round.

        Ok(BatchTxRes {
            // Placeholder txid until the real commitment tx is received from the server.
            commitment_txid: format!("pending:{}", intent_id),
        })
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
        let mut c = ArkClient::new("http://localhost:50051");
        // Should fail with a Connection error before even opening the stream.
        let result = c.notify_incoming_funds("bc1qtest", Some(1)).await;
        assert!(result.is_err());
        if let Err(ClientError::Connection(msg)) = result {
            assert!(msg.contains("Not connected"));
        } else {
            panic!("Expected Connection error, got something else");
        }
    }
}
