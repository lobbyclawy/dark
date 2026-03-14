use crate::error::{ClientError, ClientResult};
use crate::types::{Intent, ServerInfo, TxResult, Vtxo};

/// Client for communicating with an arkd-rs server.
pub struct ArkClient {
    server_url: String,
}

impl ArkClient {
    /// Create a new client connected to `server_url` (e.g. `http://localhost:50051`).
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
        }
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Get server info. (stub — real gRPC call once proto client is generated)
    pub async fn get_info(&self) -> ClientResult<ServerInfo> {
        // TODO: real tonic client call
        // For now return a stub to show the API shape
        Err(ClientError::Connection(format!(
            "gRPC client not yet wired to {}: use grpcurl for now",
            self.server_url
        )))
    }

    /// List VTXOs owned by `pubkey`.
    pub async fn list_vtxos(&self, _pubkey: &str) -> ClientResult<Vec<Vtxo>> {
        Err(ClientError::Connection("gRPC client not yet wired".into()))
    }

    /// Register an intent to receive VTXOs in the next round.
    pub async fn register_intent(&self, _intent: Intent) -> ClientResult<String> {
        Err(ClientError::Connection("gRPC client not yet wired".into()))
    }

    /// Submit an offchain transaction.
    pub async fn submit_tx(&self, _tx_hex: &str) -> ClientResult<TxResult> {
        Err(ClientError::Connection("gRPC client not yet wired".into()))
    }

    /// Board: register a new VTXO from an on-chain output.
    pub async fn board(
        &self,
        _txid: &str,
        _vout: u32,
        _amount: u64,
        _pubkey: &str,
    ) -> ClientResult<String> {
        Err(ClientError::Connection("gRPC client not yet wired".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new() {
        let c = ArkClient::new("http://localhost:50051");
        assert_eq!(c.server_url(), "http://localhost:50051");
    }

    #[test]
    fn test_client_url_stored() {
        let c = ArkClient::new("http://192.168.1.1:50051");
        assert!(c.server_url().contains("192.168.1.1"));
    }

    #[tokio::test]
    async fn test_get_info_returns_error_when_not_connected() {
        let c = ArkClient::new("http://localhost:50051");
        assert!(c.get_info().await.is_err());
    }

    #[tokio::test]
    async fn test_list_vtxos_returns_error_when_not_connected() {
        let c = ArkClient::new("http://localhost:50051");
        assert!(c.list_vtxos("pubkey123").await.is_err());
    }

    #[test]
    fn test_server_info_serde() {
        let info = crate::types::ServerInfo {
            pubkey: "abc".into(),
            network: "regtest".into(),
            round_lifetime: 512,
            unilateral_exit_delay: 1024,
            version: "0.1.0".into(),
        };
        let j = serde_json::to_string(&info).unwrap();
        let info2: crate::types::ServerInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(info2.network, "regtest");
    }
}
