use serde::Deserialize;
use std::path::Path;

/// Top-level config file structure (config.toml)
#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[allow(dead_code)] // Will be used when Bitcoin RPC is wired
    #[serde(default)]
    pub bitcoin: BitcoinSection,
    #[serde(default)]
    pub ark: ArkSection,
}

#[derive(Debug, Deserialize, Default)]
pub struct ServerSection {
    pub grpc_addr: Option<String>,
    pub rest_addr: Option<String>,
    pub require_auth: Option<bool>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub asp_key_hex: Option<String>,
    pub esplora_url: Option<String>,
    pub admin_token: Option<String>,
}

#[allow(dead_code)] // Fields will be used when Bitcoin RPC integration is wired
#[derive(Debug, Deserialize, Default)]
pub struct BitcoinSection {
    pub network: Option<String>,
    pub rpc_host: Option<String>,
    pub rpc_port: Option<u16>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ArkSection {
    pub round_duration_secs: Option<u64>,
    pub round_interval_blocks: Option<u32>,
    pub allow_csv_block_type: Option<bool>,
}

/// Load config from file path. Returns default config if file doesn't exist.
pub fn load_config(path: &Path) -> anyhow::Result<FileConfig> {
    if !path.exists() {
        tracing::warn!(path = %path.display(), "Config file not found, using defaults");
        return Ok(FileConfig::default());
    }
    let content = std::fs::read_to_string(path)?;
    let config: FileConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Config parse error in {}: {e}", path.display()))?;
    tracing::info!(path = %path.display(), "Config loaded");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_config_missing_file_returns_default() {
        let result = load_config(Path::new("/tmp/nonexistent_arkd_config.toml"));
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_load_config_parses_grpc_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[server]\ngrpc_addr = \"0.0.0.0:9999\"").unwrap();

        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.server.grpc_addr.as_deref(), Some("0.0.0.0:9999"));
    }

    #[test]
    fn test_load_config_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "{{{{not valid toml").unwrap();

        let result = load_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();

        let cfg = load_config(&path).unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.bitcoin.network.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_cli_default_config_path() {
        use crate::cli::Cli;
        use clap::Parser;

        // Parse with no args (use default)
        let cli = Cli::try_parse_from(["arkd"]).unwrap();
        assert_eq!(cli.config, "config.toml");
    }
}
