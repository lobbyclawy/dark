//! Request handlers for gRPC services

use crate::ApiResult;

/// User-facing Ark service handlers
pub mod ark_service {
    use super::*;

    /// Register for next round
    pub async fn register_for_round(_pubkey: &str, _amount: u64) -> ApiResult<String> {
        // TODO: Implement in issue #9
        Ok("placeholder-round-id".to_string())
    }

    /// Request collaborative exit
    pub async fn request_exit(_vtxo_id: &str, _destination: &str) -> ApiResult<String> {
        // TODO: Implement in issue #9
        Ok("placeholder-exit-tx".to_string())
    }

    /// Get VTXO details
    pub async fn get_vtxo(_vtxo_id: &str) -> ApiResult<Option<VtxoInfo>> {
        // TODO: Implement in issue #9
        Ok(None)
    }

    /// VTXO information returned by API
    #[derive(Debug, Clone)]
    pub struct VtxoInfo {
        pub id: String,
        pub amount: u64,
        pub pubkey: String,
        pub expiry: u64,
        pub round_id: String,
    }
}

/// Admin service handlers
pub mod admin_service {
    use super::*;

    /// Server status information
    #[derive(Debug, Clone)]
    pub struct ServerStatus {
        pub version: String,
        pub uptime_secs: u64,
        pub active_rounds: u32,
        pub total_participants: u32,
        pub total_vtxos: u64,
    }

    /// Get server status
    pub async fn get_status() -> ApiResult<ServerStatus> {
        Ok(ServerStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: 0,
            active_rounds: 0,
            total_participants: 0,
            total_vtxos: 0,
        })
    }

    /// Force start a new round
    pub async fn start_round() -> ApiResult<String> {
        // TODO: Implement in issue #9
        Ok("placeholder-round-id".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_status() {
        let status = admin_service::get_status().await.unwrap();
        assert!(!status.version.is_empty());
    }
}
