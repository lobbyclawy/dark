//! Esplora-based blockchain scanner.
//!
//! Polls an Esplora HTTP API to detect on-chain spends of watched scripts.
//! Also provides direct transaction lookup and outspend queries.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{BlockchainScanner, ScriptSpentEvent};

/// Esplora transaction response (minimal fields we care about).
#[derive(Debug, Deserialize)]
struct EsploraTx {
    txid: String,
    status: EsploraTxStatus,
    vin: Vec<EsploraVin>,
}

#[derive(Debug, Deserialize)]
struct EsploraTxStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EsploraVin {
    prevout: Option<EsploraPrevout>,
}

#[derive(Debug, Deserialize)]
struct EsploraPrevout {
    scriptpubkey: String,
}

/// Esplora outspend response for a specific output.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EsploraOutspend {
    spent: bool,
    #[serde(default)]
    txid: Option<String>,
    #[serde(default)]
    vin: Option<u32>,
    #[serde(default)]
    status: Option<EsploraTxStatus>,
}

/// Blockchain scanner that polls an Esplora HTTP API.
///
/// Watches script pubkeys and emits [`ScriptSpentEvent`]s when a watched
/// script is spent in a confirmed transaction.
///
/// Also provides direct lookup methods:
/// - `get_tx_hex` — fetch raw transaction hex by txid
/// - `is_output_spent` — check if a specific output has been spent
/// - `get_address_txs` — fetch transactions for an address
pub struct EsploraScanner {
    base_url: String,
    client: reqwest::Client,
    /// Watched script pubkeys stored as hex strings.
    watched: RwLock<HashSet<String>>,
    /// Track txids we've already notified about per script (hex) to avoid duplicates.
    seen_txids: RwLock<HashMap<String, HashSet<String>>>,
    sender: broadcast::Sender<ScriptSpentEvent>,
    poll_interval: Duration,
}

impl EsploraScanner {
    /// Create a new Esplora scanner.
    ///
    /// # Arguments
    /// * `base_url` — Esplora API base URL (e.g. `https://blockstream.info/testnet/api`)
    /// * `poll_interval_secs` — How often to poll for new transactions
    pub fn new(base_url: &str, poll_interval_secs: u64) -> Self {
        let (sender, _) = broadcast::channel(256);
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            watched: RwLock::new(HashSet::new()),
            seen_txids: RwLock::new(HashMap::new()),
            sender,
            poll_interval: Duration::from_secs(poll_interval_secs),
        }
    }

    /// Return the base URL (useful for diagnostics / tests).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Start the background polling loop. Call once at startup.
    ///
    /// Spawns a tokio task that periodically checks all watched scripts
    /// for on-chain spends.
    pub fn start_polling(self: Arc<Self>) {
        tokio::spawn(async move {
            debug!("EsploraScanner: polling loop started");
            loop {
                self.poll_once().await;
                tokio::time::sleep(self.poll_interval).await;
            }
        });
    }

    // ── Direct Esplora API methods ──────────────────────────────────

    /// Fetch a raw transaction as hex by txid.
    ///
    /// Returns `Ok(Some(hex))` if found, `Ok(None)` if the API returns 404.
    pub async fn get_tx_hex(&self, txid: &str) -> ArkResult<Option<String>> {
        let url = format!("{}/tx/{}/hex", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let hex = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to read tx hex: {e}")))?;

        Ok(Some(hex.trim().to_string()))
    }

    /// Check whether a specific transaction output has been spent.
    ///
    /// Queries `GET /tx/{txid}/outspend/{vout}` and returns the `spent` flag.
    pub async fn is_output_spent(&self, txid: &str, vout: u32) -> ArkResult<bool> {
        let url = format!("{}/tx/{}/outspend/{}", self.base_url, txid, vout);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let outspend: EsploraOutspend = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse outspend: {e}")))?;

        Ok(outspend.spent)
    }

    /// Fetch transactions for a given address.
    ///
    /// Queries `GET /address/{addr}/txs` and returns the raw JSON as
    /// a vector of `serde_json::Value`.
    pub async fn get_address_txs(&self, address: &str) -> ArkResult<Vec<serde_json::Value>> {
        let url = format!("{}/address/{}/txs", self.base_url, address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let txs: Vec<serde_json::Value> = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse address txs: {e}")))?;

        Ok(txs)
    }

    // ── Internal polling helpers ────────────────────────────────────

    /// Run a single polling cycle across all watched scripts.
    async fn poll_once(&self) {
        let scripts: Vec<String> = {
            let watched = self.watched.read().await;
            watched.iter().cloned().collect()
        };

        for script_hex in scripts {
            if let Err(e) = self.check_script(&script_hex).await {
                warn!(
                    script = %script_hex,
                    error = %e,
                    "EsploraScanner: failed to check script"
                );
            }
        }
    }

    /// Check a single script for new spending transactions.
    async fn check_script(
        &self,
        script_hex: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Esplora uses the script hash (SHA256 of the scriptpubkey bytes, reversed)
        let script_bytes = hex::decode(script_hex)?;
        let script_hash = {
            use bitcoin::hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(&script_bytes);
            let mut bytes = hash.to_byte_array();
            bytes.reverse();
            hex::encode(bytes)
        };

        let url = format!("{}/scripthash/{}/txs", self.base_url, script_hash);
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            warn!(
                url = %url,
                status = %resp.status(),
                "EsploraScanner: non-success response"
            );
            return Ok(());
        }

        let txs: Vec<EsploraTx> = resp.json().await?;

        for tx in txs {
            // Only care about confirmed transactions
            if !tx.status.confirmed {
                continue;
            }

            let block_height = tx.status.block_height.unwrap_or(0);

            // Check if any input spends our watched script
            let spends_watched = tx.vin.iter().any(|vin| {
                vin.prevout
                    .as_ref()
                    .map(|p| p.scriptpubkey == *script_hex)
                    .unwrap_or(false)
            });

            if !spends_watched {
                continue;
            }

            // Check if we've already notified about this txid for this script
            let already_seen = {
                let seen = self.seen_txids.read().await;
                seen.get(script_hex)
                    .map(|s| s.contains(&tx.txid))
                    .unwrap_or(false)
            };

            if already_seen {
                continue;
            }

            // Mark as seen
            {
                let mut seen = self.seen_txids.write().await;
                seen.entry(script_hex.to_string())
                    .or_default()
                    .insert(tx.txid.clone());
            }

            let event = ScriptSpentEvent {
                script_pubkey: script_bytes.clone(),
                spending_txid: tx.txid.clone(),
                block_height,
            };

            debug!(
                txid = %tx.txid,
                height = block_height,
                "EsploraScanner: script spent on-chain"
            );

            if self.sender.send(event).is_err() {
                // No active receivers — that's fine
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BlockchainScanner for EsploraScanner {
    async fn watch_script(&self, script_pubkey: Vec<u8>) -> ArkResult<()> {
        let hex_key = hex::encode(&script_pubkey);
        self.watched.write().await.insert(hex_key);
        Ok(())
    }

    async fn unwatch_script(&self, script_pubkey: &[u8]) -> ArkResult<()> {
        let hex_key = hex::encode(script_pubkey);
        self.watched.write().await.remove(&hex_key);
        // Also clean up seen txids for this script
        self.seen_txids.write().await.remove(&hex_key);
        Ok(())
    }

    fn notification_channel(&self) -> broadcast::Receiver<ScriptSpentEvent> {
        self.sender.subscribe()
    }

    async fn tip_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(e.to_string()))?;

        let height: u32 = text.trim().parse().map_err(|e: std::num::ParseIntError| {
            ArkError::Internal(format!(
                "failed to parse tip height '{}': {}",
                text.trim(),
                e
            ))
        })?;

        Ok(height)
    }

    async fn is_utxo_unspent(&self, outpoint: &dark_core::domain::VtxoOutpoint) -> ArkResult<bool> {
        // Delegates to the existing is_output_spent method, inverting the result
        let spent = self.is_output_spent(&outpoint.txid, outpoint.vout).await?;
        Ok(!spent)
    }

    async fn get_tx_output(&self, txid: &str, vout: u32) -> ArkResult<Option<(u64, Vec<u8>)>> {
        let hex_str = match self.get_tx_hex(txid).await? {
            Some(h) => h,
            None => return Ok(None),
        };
        let raw = hex::decode(&hex_str)
            .map_err(|e| ArkError::Internal(format!("Failed to decode tx hex: {e}")))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)
            .map_err(|e| ArkError::Internal(format!("Failed to deserialize tx: {e}")))?;
        match tx.output.get(vout as usize) {
            Some(out) => Ok(Some((out.value.to_sat(), out.script_pubkey.to_bytes()))),
            None => Ok(None),
        }
    }

    async fn is_tx_confirmed(&self, txid: &str) -> ArkResult<bool> {
        // Use get_tx_hex — returns Some(_) if the transaction is known to Esplora.
        // Esplora returns confirmed txs; unconfirmed may also appear but we check status.
        let url = format!("{}/tx/{}/status", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {url} returned {}",
                resp.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct TxStatus {
            confirmed: bool,
        }

        let status: TxStatus = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse tx status: {e}")))?;

        Ok(status.confirmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esplora_scanner_construction() {
        let scanner = EsploraScanner::new("https://blockstream.info/testnet/api", 30);
        assert_eq!(scanner.base_url, "https://blockstream.info/testnet/api");
        assert_eq!(scanner.poll_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_trailing_slash_stripped() {
        let scanner = EsploraScanner::new("http://localhost:3000/", 10);
        assert_eq!(scanner.base_url, "http://localhost:3000");
    }

    #[tokio::test]
    async fn test_esplora_scanner_watch_unwatch() {
        let scanner = EsploraScanner::new("http://localhost:3000", 10);
        let script = vec![0x00, 0x14, 0xab, 0xcd];

        assert!(scanner.watch_script(script.clone()).await.is_ok());
        {
            let watched = scanner.watched.read().await;
            assert!(watched.contains(&hex::encode(&script)));
        }

        assert!(scanner.unwatch_script(&script).await.is_ok());
        {
            let watched = scanner.watched.read().await;
            assert!(!watched.contains(&hex::encode(&script)));
        }
    }

    #[tokio::test]
    async fn test_unwatch_clears_seen_txids() {
        let scanner = EsploraScanner::new("http://localhost:3000", 10);
        let script = vec![0xab, 0xcd];
        let script_hex = hex::encode(&script);

        // Manually inject a seen txid
        scanner.watch_script(script.clone()).await.unwrap();
        {
            let mut seen = scanner.seen_txids.write().await;
            seen.entry(script_hex.clone())
                .or_default()
                .insert("deadbeef".to_string());
        }

        // Unwatch should clean up seen_txids too
        scanner.unwatch_script(&script).await.unwrap();
        {
            let seen = scanner.seen_txids.read().await;
            assert!(!seen.contains_key(&script_hex));
        }
    }

    #[tokio::test]
    async fn test_esplora_scanner_as_trait_object() {
        let scanner: Arc<dyn BlockchainScanner> =
            Arc::new(EsploraScanner::new("http://localhost:3000", 10));
        assert!(scanner.watch_script(vec![0x01]).await.is_ok());
        let _rx = scanner.notification_channel();
    }

    // ── Mock-based integration tests ────────────────────────────────

    #[tokio::test]
    async fn test_get_tx_hex_found() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abc123def456";
        let mock_hex = "0200000001abcdef";

        let mock = server
            .mock("GET", format!("/tx/{}/hex", txid).as_str())
            .with_status(200)
            .with_body(mock_hex)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        let result = scanner.get_tx_hex(txid).await.unwrap();
        assert_eq!(result, Some(mock_hex.to_string()));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_tx_hex_not_found() {
        let mut server = mockito::Server::new_async().await;
        let txid = "nonexistent";

        let mock = server
            .mock("GET", format!("/tx/{}/hex", txid).as_str())
            .with_status(404)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        let result = scanner.get_tx_hex(txid).await.unwrap();
        assert_eq!(result, None);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_is_output_spent_true() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abc123";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"def456","vin":0,"status":{"confirmed":true,"block_height":800000}}"#)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        assert!(scanner.is_output_spent(txid, 0).await.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_is_output_spent_false() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abc123";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/1", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        assert!(!scanner.is_output_spent(txid, 1).await.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_get_address_txs() {
        let mut server = mockito::Server::new_async().await;
        let addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        let mock = server
            .mock("GET", format!("/address/{}/txs", addr).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"[{"txid":"aaa","status":{"confirmed":true,"block_height":100}}]"#)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        let txs = scanner.get_address_txs(addr).await.unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["txid"], "aaa");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_tip_height() {
        let mut server = mockito::Server::new_async().await;

        let mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("890123")
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        let height = scanner.tip_height().await.unwrap();
        assert_eq!(height, 890123);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_poll_emits_event_for_spent_script() {
        let mut server = mockito::Server::new_async().await;

        // Script we're watching: 0x0014abcd
        let script_hex = "0014abcd";
        let script_bytes = hex::decode(script_hex).unwrap();

        // Compute the scripthash the scanner will use
        let script_hash = {
            use bitcoin::hashes::{sha256, Hash};
            let hash = sha256::Hash::hash(&script_bytes);
            let mut bytes = hash.to_byte_array();
            bytes.reverse();
            hex::encode(bytes)
        };

        let mock = server
            .mock("GET", format!("/scripthash/{}/txs", script_hash).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"[{{
                    "txid":"spending_tx_001",
                    "status":{{"confirmed":true,"block_height":500}},
                    "vin":[{{"prevout":{{"scriptpubkey":"{}"}}}}]
                }}]"#,
                script_hex
            ))
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        scanner.watch_script(script_bytes).await.unwrap();

        let mut rx = scanner.notification_channel();
        scanner.poll_once().await;

        let event = rx.try_recv().expect("expected a ScriptSpentEvent");
        assert_eq!(event.spending_txid, "spending_tx_001");
        assert_eq!(event.block_height, 500);
        assert_eq!(hex::encode(&event.script_pubkey), script_hex);

        mock.assert_async().await;
    }
}
