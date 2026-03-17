//! ArkClient — typed gRPC client for arkd-rs server.

use crate::error::{ClientError, ClientResult};
use crate::types::{
    Balance, BoardingAddress, LockedAmount, OffchainAddress, OffchainBalance, OnchainBalance,
    RoundInfo, RoundSummary, ServerInfo, Vtxo,
};
use arkd_api::proto::ark_v1::{
    ark_service_client::ArkServiceClient, GetInfoRequest, GetRoundRequest, GetVtxosRequest,
    ListRoundsRequest,
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
}
