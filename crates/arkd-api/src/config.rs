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
    fn test_admin_addr_explicit() {
        let config = ServerConfig {
            admin_grpc_addr: Some("127.0.0.1:8888".to_string()),
            ..Default::default()
        };
        assert_eq!(config.admin_addr(), "127.0.0.1:8888");
    }
}
