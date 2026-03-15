//! ArkClient — typed gRPC client for arkd-rs server.

use crate::error::{ClientError, ClientResult};
use crate::types::{RoundInfo, RoundSummary, ServerInfo, Vtxo};
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
