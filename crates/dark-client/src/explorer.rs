//! Esplora block explorer client for the Ark client SDK.
//!
//! Provides HTTP access to an Esplora/Mempool API for querying UTXOs,
//! broadcasting transactions, and checking transaction status.
//! Mirrors Go's `client-lib/explorer` functionality.

use serde::{Deserialize, Serialize};

use crate::error::{ClientError, ClientResult};

/// A UTXO returned by the Esplora API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
    /// Confirmation status.
    pub status: TxStatus,
}

/// Transaction confirmation status from Esplora.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatus {
    /// Whether the transaction is confirmed.
    pub confirmed: bool,
    /// Block height (if confirmed).
    pub block_height: Option<u64>,
    /// Block hash (if confirmed).
    pub block_hash: Option<String>,
    /// Block time (if confirmed).
    pub block_time: Option<u64>,
}

/// Full transaction info from Esplora.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInfo {
    /// Transaction ID.
    pub txid: String,
    /// Fee paid in satoshis.
    pub fee: u64,
    /// Confirmation status.
    pub status: TxStatus,
}

/// HTTP client for an Esplora-compatible block explorer API.
///
/// Supports standard Esplora endpoints for UTXO queries, transaction
/// broadcasting, and status checks.
#[derive(Debug, Clone)]
pub struct EsploraExplorer {
    base_url: String,
    client: reqwest::Client,
}

impl EsploraExplorer {
    /// Create a new explorer client pointing at `base_url`.
    ///
    /// # Example
    /// ```
    /// use dark_client::explorer::EsploraExplorer;
    /// let explorer = EsploraExplorer::new("https://blockstream.info/api");
    /// ```
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut url: String = base_url.into();
        // Strip trailing slash for consistent URL building.
        while url.ends_with('/') {
            url.pop();
        }
        Self {
            base_url: url,
            client: reqwest::Client::new(),
        }
    }

    /// Create with a custom `reqwest::Client` (for timeouts, proxies, etc.).
    pub fn with_client(base_url: impl Into<String>, client: reqwest::Client) -> Self {
        let mut url: String = base_url.into();
        while url.ends_with('/') {
            url.pop();
        }
        Self {
            base_url: url,
            client,
        }
    }

    /// Return the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get UTXOs for a Bitcoin address.
    pub async fn get_utxos(&self, address: &str) -> ClientResult<Vec<Utxo>> {
        let url = format!("{}/address/{}/utxo", self.base_url, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("GET {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "GET {url} returned {status}: {body}"
            )));
        }

        resp.json::<Vec<Utxo>>()
            .await
            .map_err(|e| ClientError::Explorer(format!("Failed to parse UTXOs: {e}")))
    }

    /// Get transaction info by txid.
    pub async fn get_tx(&self, txid: &str) -> ClientResult<TxInfo> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("GET {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "GET {url} returned {status}: {body}"
            )));
        }

        resp.json::<TxInfo>()
            .await
            .map_err(|e| ClientError::Explorer(format!("Failed to parse tx info: {e}")))
    }

    /// Get transaction status (confirmed/unconfirmed).
    pub async fn get_tx_status(&self, txid: &str) -> ClientResult<TxStatus> {
        let url = format!("{}/tx/{}/status", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("GET {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "GET {url} returned {status}: {body}"
            )));
        }

        resp.json::<TxStatus>()
            .await
            .map_err(|e| ClientError::Explorer(format!("Failed to parse tx status: {e}")))
    }

    /// Broadcast a raw transaction (hex-encoded).
    ///
    /// Returns the txid on success.
    pub async fn broadcast_tx(&self, tx_hex: &str) -> ClientResult<String> {
        let url = format!("{}/tx", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(tx_hex.to_string())
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("POST {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "Broadcast failed ({status}): {body}"
            )));
        }

        resp.text()
            .await
            .map(|s| s.trim().to_string())
            .map_err(|e| ClientError::Explorer(format!("Failed to read broadcast response: {e}")))
    }

    /// Get the recommended fee rates (in sat/vB).
    ///
    /// Returns a map of confirmation targets to fee rates.
    pub async fn get_fee_estimates(&self) -> ClientResult<std::collections::HashMap<String, f64>> {
        let url = format!("{}/fee-estimates", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("GET {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "GET {url} returned {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| ClientError::Explorer(format!("Failed to parse fee estimates: {e}")))
    }

    /// Get the current block tip height.
    pub async fn get_tip_height(&self) -> ClientResult<u64> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::Explorer(format!("GET {url} failed: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(ClientError::Explorer(format!(
                "GET {url} returned {status}: {body}"
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ClientError::Explorer(format!("Failed to read tip height: {e}")))?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| ClientError::Explorer(format!("Invalid tip height '{text}': {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explorer_new() {
        let e = EsploraExplorer::new("https://blockstream.info/api");
        assert_eq!(e.base_url(), "https://blockstream.info/api");
    }

    #[test]
    fn test_explorer_strips_trailing_slash() {
        let e = EsploraExplorer::new("https://blockstream.info/api/");
        assert_eq!(e.base_url(), "https://blockstream.info/api");
    }

    #[test]
    fn test_utxo_deserialize() {
        let json = r#"[{
            "txid": "abc123",
            "vout": 0,
            "value": 50000,
            "status": {
                "confirmed": true,
                "block_height": 100,
                "block_hash": "def456",
                "block_time": 1700000000
            }
        }]"#;
        let utxos: Vec<Utxo> = serde_json::from_str(json).unwrap();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "abc123");
        assert_eq!(utxos[0].value, 50000);
        assert!(utxos[0].status.confirmed);
    }

    #[test]
    fn test_tx_status_unconfirmed() {
        let json = r#"{"confirmed": false}"#;
        let status: TxStatus = serde_json::from_str(json).unwrap();
        assert!(!status.confirmed);
        assert!(status.block_height.is_none());
    }
}
