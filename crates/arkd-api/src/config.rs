//! API server configuration

use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// gRPC listen address (user-facing ArkService)
    pub grpc_addr: String,

    /// Admin gRPC listen address (operator AdminService).
    /// If not set, derived from grpc_addr by incrementing the port.
    pub admin_grpc_addr: Option<String>,

    /// REST listen address (optional)
    pub rest_addr: Option<String>,

    /// Enable TLS
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<String>,

    /// TLS key path
    pub tls_key_path: Option<String>,

    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    /// Enable request logging
    #[serde(default = "default_true")]
    pub enable_logging: bool,

    /// Admin token (for admin API access)
    pub admin_token: Option<String>,

    /// Require authentication for protected endpoints.
    /// When false, unauthenticated requests use a placeholder identity (dev mode).
    /// When true, authentication is strictly enforced (production).
    #[serde(default)]
    pub require_auth: bool,

    /// gRPC endpoint for remote signer process (key isolation).
    /// If `None`, local signing is used. Example: `"http://127.0.0.1:7072"`
    #[serde(default)]
    pub remote_signer_url: Option<String>,

    /// Esplora API URL for blockchain scanning.
    /// If `None`, a no-op scanner is used (no on-chain monitoring).
    /// Example: `"https://blockstream.info/testnet/api"`
    #[serde(default)]
    pub esplora_url: Option<String>,

    /// Hex-encoded 32-byte secret key for the ASP local signer.
    /// When set, the server uses `LocalSigner::from_hex` instead of a remote signer.
    /// Generate with: `openssl rand -hex 32`
    #[serde(default)]
    pub asp_key_hex: Option<String>,

    /// Use block-height-based round scheduling instead of time-based.
    #[serde(default)]
    pub allow_csv_block_type: bool,

    /// Seconds between automatic round triggers (time-based scheduling). Default: 30.
    #[serde(default = "default_round_duration_secs")]
    pub round_duration_secs: u64,

    /// Number of blocks between round triggers when block-based scheduling is enabled.
    #[serde(default = "default_round_interval_blocks")]
    pub round_interval_blocks: u32,
}

fn default_max_connections() -> usize {
    1000
}

fn default_request_timeout() -> u64 {
    30
}

fn default_true() -> bool {
    true
}

impl ServerConfig {
    /// Return the admin gRPC address.
    ///
    /// If `admin_grpc_addr` is set, returns that. Otherwise derives from
    /// `grpc_addr` by incrementing the port by 1.
    pub fn admin_addr(&self) -> String {
        if let Some(ref addr) = self.admin_grpc_addr {
            return addr.clone();
        }
        // Parse port from grpc_addr, increment by 1
        if let Some(colon_pos) = self.grpc_addr.rfind(':') {
            let host = &self.grpc_addr[..colon_pos];
            if let Ok(port) = self.grpc_addr[colon_pos + 1..].parse::<u16>() {
                return format!("{}:{}", host, port + 1);
            }
        }
        // Fallback
        "0.0.0.0:7071".to_string()
    }
}

fn default_round_interval_blocks() -> u32 {
    6
}
fn default_round_duration_secs() -> u64 {
    30
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: "0.0.0.0:7070".to_string(),
            admin_grpc_addr: Some("0.0.0.0:7071".to_string()),
            rest_addr: None,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout(),
            enable_logging: true,
            admin_token: None,
            require_auth: false, // Dev mode by default
            remote_signer_url: None,
            esplora_url: None,
            asp_key_hex: None,
            allow_csv_block_type: false,
            round_interval_blocks: 6,
            round_duration_secs: 30,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.grpc_addr, "0.0.0.0:7070");
        assert_eq!(config.admin_addr(), "0.0.0.0:7071");
    }

    #[test]
    fn test_admin_addr_derived() {
        let config = ServerConfig {
            admin_grpc_addr: None,
            grpc_addr: "0.0.0.0:9090".to_string(),
            ..Default::default()
        };
        assert_eq!(config.admin_addr(), "0.0.0.0:9091");
    }

    #[test]
    fn test_config_asp_key_defaults_to_none() {
        let config = ServerConfig::default();
        assert!(config.asp_key_hex.is_none());
    }

    #[test]
    fn test_admin_addr_explicit() {
        let config = ServerConfig {
            admin_grpc_addr: Some("127.0.0.1:8888".to_string()),
            ..Default::default()
        };
        assert_eq!(config.admin_addr(), "127.0.0.1:8888");
    }
}
