//! Runtime configuration for the REST daemon.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    /// Socket to bind the HTTP server on.
    pub listen_addr: SocketAddr,
    /// URL of the upstream dark gRPC server.
    pub dark_grpc_url: String,
    /// Skip macaroon authentication on /v1 routes. Dev-only.
    pub auth_disabled: bool,
    /// Macaroon root key for verifying bearer tokens. Must match the dark
    /// server's root key. When `None` and `auth_disabled` is false, the
    /// daemon refuses all authenticated requests (fail-closed).
    pub macaroon_root_key: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 7072)),
            dark_grpc_url: "http://localhost:7070".to_string(),
            auth_disabled: true,
            macaroon_root_key: None,
        }
    }
}

/// Parse a hex or `@/path/to/file` specification for the macaroon root key.
///
/// - `"deadbeef..."` → hex-decoded bytes.
/// - `"@/path"` → read the file contents verbatim (raw bytes).
/// - `None` → no key configured.
pub fn load_root_key(spec: Option<&str>) -> anyhow::Result<Option<Vec<u8>>> {
    match spec {
        None | Some("") => Ok(None),
        Some(s) if s.starts_with('@') => {
            let path = PathBuf::from(&s[1..]);
            let bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("read macaroon root key from {path:?}: {e}"))?;
            Ok(Some(bytes))
        }
        Some(s) => {
            let bytes = hex::decode(s)
                .map_err(|e| anyhow::anyhow!("macaroon root key must be hex or '@path': {e}"))?;
            Ok(Some(bytes))
        }
    }
}
