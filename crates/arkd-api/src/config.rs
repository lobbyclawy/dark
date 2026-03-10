//! API server configuration

use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// gRPC listen address
    pub grpc_addr: String,

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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: "[::1]:50051".to_string(),
            rest_addr: Some("127.0.0.1:8080".to_string()),
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            max_connections: default_max_connections(),
            request_timeout_secs: default_request_timeout(),
            enable_logging: true,
            admin_token: None,
        }
    }
}
