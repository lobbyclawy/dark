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
    block_sender: broadcast::Sender<dark_core::ports::NewBlockEvent>,
    /// Last known chain tip height, used to detect new blocks.
    last_tip: std::sync::atomic::AtomicU32,
    poll_interval: Duration,
    /// Optional Bitcoin Core RPC URL for fast tx confirmation checks.
    /// Bypasses Esplora/chopsticks indexing lag.
    rpc_url: Option<String>,
}

impl EsploraScanner {
    /// Create a new Esplora scanner.
    ///
    /// # Arguments
    /// * `base_url` — Esplora API base URL (e.g. `https://blockstream.info/testnet/api`)
    /// * `poll_interval_secs` — How often to poll for new transactions
    pub fn new(base_url: &str, poll_interval_secs: u64) -> Self {
        let (sender, _) = broadcast::channel(256);
        let (block_sender, _) = broadcast::channel(16);
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            watched: RwLock::new(HashSet::new()),
            seen_txids: RwLock::new(HashMap::new()),
            sender,
            block_sender,
            last_tip: std::sync::atomic::AtomicU32::new(0),
            poll_interval: Duration::from_secs(poll_interval_secs),
            rpc_url: None,
        }
    }

    /// Set the Bitcoin Core RPC URL for fast confirmation checks.
    /// Format: `http://user:pass@host:port`
    pub fn with_rpc_url(mut self, url: String) -> Self {
        self.rpc_url = Some(url);
        self
    }

    /// Fetch the chain tip height via Bitcoin Core RPC. Used as the fast
    /// path of [`tip_height_internal`] so block-driven event detection is
    /// not gated on chopsticks/electrs indexing latency under CI load.
    async fn rpc_get_block_count(&self) -> Option<u32> {
        let rpc_url = self.rpc_url.as_ref()?;
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "dark",
            "method": "getblockcount",
            "params": []
        });
        let resp = self.client.post(rpc_url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        json.get("result")?.as_u64().map(|h| h as u32)
    }

    /// Check tx confirmation via Bitcoin Core RPC (no indexing lag).
    /// Uses `gettxout` to check if ANY output of the TX exists as a UTXO,
    /// which works even when the TX was broadcast via chopsticks and hasn't
    /// been indexed by Esplora/electrs yet.
    async fn rpc_is_tx_confirmed(&self, txid: &str) -> Option<bool> {
        let rpc_url = self.rpc_url.as_ref()?;
        // Try gettxout for vout 0 (include_mempool=false for confirmed only)
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "dark",
            "method": "gettxout",
            "params": [txid, 0, false]
        });
        let resp = self.client.post(rpc_url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        // gettxout returns null result if UTXO doesn't exist (spent or never confirmed)
        if json.get("result")?.is_null() {
            // UTXO at vout 0 not found — but it might have been spent already.
            // Fall back to getrawtransaction to check if the TX exists at all.
            let body2 = serde_json::json!({
                "jsonrpc": "1.0",
                "id": "dark",
                "method": "getrawtransaction",
                "params": [txid, true]
            });
            let resp2 = self.client.post(rpc_url).json(&body2).send().await.ok()?;
            let json2: serde_json::Value = resp2.json().await.ok()?;
            let result = json2.get("result")?;
            if result.is_null() {
                return Some(false); // TX truly not found
            }
            let confirmations = result.get("confirmations")?.as_u64()?;
            return Some(confirmations > 0);
        }
        // UTXO exists → TX is confirmed
        Some(true)
    }

    /// Get tx confirmation height via Bitcoin Core RPC.
    async fn rpc_get_tx_confirmation_height(&self, txid: &str) -> Option<u32> {
        let rpc_url = self.rpc_url.as_ref()?;
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "dark",
            "method": "getrawtransaction",
            "params": [txid, true]
        });
        let resp = self.client.post(rpc_url).json(&body).send().await.ok()?;
        let json: serde_json::Value = resp.json().await.ok()?;
        let result = json.get("result")?;
        let confirmations = result.get("confirmations")?.as_u64()?;
        if confirmations == 0 {
            return None;
        }
        // blockhash → getblockheader → height
        let blockhash = result.get("blockhash")?.as_str()?;
        let body2 = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "dark",
            "method": "getblockheader",
            "params": [blockhash]
        });
        let resp2 = self.client.post(rpc_url).json(&body2).send().await.ok()?;
        let json2: serde_json::Value = resp2.json().await.ok()?;
        json2
            .get("result")?
            .get("height")?
            .as_u64()
            .map(|h| h as u32)
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
        // Spawn the script-spend polling loop (existing behavior).
        let scanner = Arc::clone(&self);
        tokio::spawn(async move {
            debug!("EsploraScanner: script polling loop started");
            loop {
                scanner.poll_once().await;
                tokio::time::sleep(scanner.poll_interval).await;
            }
        });

        // Spawn a lightweight block-tip polling loop.
        //
        // Emits `NewBlockEvent` when the chain tip advances so consumers
        // can react without waiting for the heavier script-spend cycle.
        // The cadence tracks `poll_interval` capped at 3 s: production
        // still polls every 3 s (the prior default), while regtest —
        // where the auto-miner advances the tip every 2 s and the Go
        // E2E suite gives the server a few seconds to react to a fraud
        // unroll — gets the same fast 1 s rhythm as the script-spend
        // poller. Without this, block events arrived every ~6 s under
        // CI load (request latency stacked on top of the fixed 3 s
        // sleep), pushing fraud detection past the test budget at
        // `vendor/arkd/internal/test/e2e/e2e_test.go:2119`.
        let block_poll = std::cmp::min(self.poll_interval, Duration::from_secs(3));
        tokio::spawn(async move {
            debug!("EsploraScanner: block-tip polling loop started");
            loop {
                self.check_new_block().await;
                tokio::time::sleep(block_poll).await;
            }
        });
    }

    /// Check if a new block has been mined and emit a notification.
    async fn check_new_block(&self) {
        match self.tip_height_internal().await {
            Ok(height) if height > 0 => {
                let prev = self
                    .last_tip
                    .swap(height, std::sync::atomic::Ordering::Relaxed);
                if prev > 0 && height > prev {
                    debug!(
                        prev_height = prev,
                        new_height = height,
                        "EsploraScanner: new block detected"
                    );
                    let _ = self
                        .block_sender
                        .send(dark_core::ports::NewBlockEvent { height });
                }
            }
            Ok(_) => {}
            Err(e) => {
                debug!(error = %e, "EsploraScanner: failed to fetch tip height");
            }
        }
    }

    /// Internal tip_height fetch (avoids trait dispatch).
    ///
    /// Prefers Bitcoin Core RPC (`getblockcount`) when an `rpc_url` is
    /// configured, falling back to chopsticks/Esplora HTTP when RPC is
    /// unavailable. The RPC path is local IPC and returns near-instantly
    /// even under heavy CI load, whereas the chopsticks `/blocks/tip/height`
    /// endpoint stacks request latency on top of the polling sleep —
    /// observed at ~5 s/cycle in TestReactToFraud shard 3 logs, which
    /// pushed block-driven fraud detection past the 8 s phase-2 budget at
    /// `vendor/arkd/internal/test/e2e/e2e_test.go:2119`.
    async fn tip_height_internal(&self) -> ArkResult<u32> {
        if let Some(h) = self.rpc_get_block_count().await {
            return Ok(h);
        }
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

    /// Check whether a specific transaction output has been spent by a
    /// **confirmed** on-chain transaction.
    ///
    /// Queries `GET /tx/{txid}/outspend/{vout}`.  Esplora's `spent` flag is
    /// true for both mempool and confirmed spenders; fraud reaction and
    /// unroll detection must ignore mempool-only spenders (they can be
    /// double-spent or RBF'd before confirmation).  We therefore gate the
    /// result on `status.confirmed` so this method matches Go arkd's
    /// block-confirmed-only scanner notification semantic.
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

        let confirmed_spend =
            outspend.spent && outspend.status.as_ref().is_some_and(|s| s.confirmed);
        Ok(confirmed_spend)
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
        self.tip_height_internal().await
    }

    async fn is_utxo_unspent(&self, outpoint: &dark_core::domain::VtxoOutpoint) -> ArkResult<bool> {
        // Delegates to the existing is_output_spent method, inverting the result
        let spent = self.is_output_spent(&outpoint.txid, outpoint.vout).await?;
        Ok(!spent)
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

        if status.confirmed {
            return Ok(true);
        }

        // Esplora says not confirmed — try Bitcoin Core RPC as fallback
        // (no indexing lag, immediate block data access).
        if let Some(true) = self.rpc_is_tx_confirmed(txid).await {
            return Ok(true);
        }

        Ok(false)
    }

    async fn is_output_spent(&self, txid: &str, vout: u32) -> ArkResult<bool> {
        let esplora_result = self.is_output_spent(txid, vout).await?;
        if esplora_result {
            return Ok(true);
        }
        // Esplora says not spent — try Bitcoin Core RPC as fallback.
        // gettxout returns null if the output was spent or TX unknown.
        // We check gettxout(false) for confirmed-only: if null AND the TX
        // has confirmations, the output was spent on-chain.
        if let Some(rpc_url) = &self.rpc_url {
            let body = serde_json::json!({
                "jsonrpc": "1.0",
                "id": "dark",
                "method": "gettxout",
                "params": [txid, vout, false]
            });
            if let Ok(resp) = self.client.post(rpc_url).json(&body).send().await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(result) = json.get("result") {
                        if result.is_null() {
                            // Output not in UTXO set. Verify the TX exists
                            // (to distinguish "spent" from "never existed").
                            let body2 = serde_json::json!({
                                "jsonrpc": "1.0",
                                "id": "dark",
                                "method": "getrawtransaction",
                                "params": [txid, true]
                            });
                            if let Ok(resp2) = self.client.post(rpc_url).json(&body2).send().await {
                                if let Ok(json2) = resp2.json::<serde_json::Value>().await {
                                    if let Some(r) = json2.get("result") {
                                        if !r.is_null() {
                                            // TX exists but output not in UTXO set → spent
                                            return Ok(true);
                                        }
                                    }
                                }
                            }
                        }
                        // Output exists in UTXO set → not spent
                    }
                }
            }
        }
        Ok(false)
    }

    async fn get_tx_confirmation_height(&self, txid: &str) -> ArkResult<Option<u32>> {
        let url = format!("{}/tx/{}/status", self.base_url, txid);
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
                "Esplora GET {url} returned {}",
                resp.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct TxStatus {
            confirmed: bool,
            block_height: Option<u32>,
        }

        let status: TxStatus = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse tx status: {e}")))?;

        if status.confirmed {
            return Ok(status.block_height);
        }

        // Esplora says not confirmed — try Bitcoin Core RPC as fallback.
        if let Some(height) = self.rpc_get_tx_confirmation_height(txid).await {
            return Ok(Some(height));
        }

        Ok(None)
    }

    async fn find_confirmed_tx_for_script(
        &self,
        script_hex: &str,
        amount: u64,
    ) -> ArkResult<Option<String>> {
        // Compute the scripthash for Esplora (SHA256 of the raw script, reversed).
        let script_bytes = match hex::decode(script_hex) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        use bitcoin::hashes::{sha256, Hash};
        let hash = sha256::Hash::hash(&script_bytes);
        let mut reversed = hash.to_byte_array();
        reversed.reverse();
        let scripthash = hex::encode(reversed);

        // Query Esplora for UTXOs at this scripthash.
        let url = format!("{}/scripthash/{}/utxo", self.base_url, scripthash);
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };
        if !resp.status().is_success() {
            return Ok(None);
        }

        #[derive(serde::Deserialize)]
        #[allow(dead_code)]
        struct EsploraUtxo {
            txid: String,
            vout: u32,
            value: u64,
            status: EsploraUtxoStatus,
        }
        #[derive(serde::Deserialize)]
        struct EsploraUtxoStatus {
            confirmed: bool,
        }

        let utxos: Vec<EsploraUtxo> = match resp.json().await {
            Ok(u) => u,
            Err(_) => return Ok(None),
        };

        // Find a confirmed UTXO with the expected amount.
        for utxo in &utxos {
            if utxo.status.confirmed && utxo.value == amount {
                return Ok(Some(utxo.txid.clone()));
            }
        }

        // Also check spent transaction history for this scripthash.
        let url2 = format!("{}/scripthash/{}/txs", self.base_url, scripthash);
        if let Ok(resp2) = self.client.get(&url2).send().await {
            if resp2.status().is_success() {
                if let Ok(txs) = resp2.json::<Vec<serde_json::Value>>().await {
                    for tx in &txs {
                        let confirmed = tx
                            .get("status")
                            .and_then(|s| s.get("confirmed"))
                            .and_then(|c| c.as_bool())
                            .unwrap_or(false);
                        if !confirmed {
                            continue;
                        }
                        // Check outputs for matching script + amount
                        if let Some(vouts) = tx.get("vout").and_then(|v| v.as_array()) {
                            for vout in vouts {
                                let val = vout.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
                                let spk = vout
                                    .get("scriptpubkey")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if val == amount && spk == script_hex {
                                    if let Some(txid) = tx.get("txid").and_then(|t| t.as_str()) {
                                        return Ok(Some(txid.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    async fn broadcast_raw_tx(&self, tx_hex: &str) -> ArkResult<()> {
        if let Some(rpc_url) = &self.rpc_url {
            // TRUC v3 tree TXs have 0 fee — Bitcoin Core's sendrawtransaction
            // rejects them. Use testmempoolaccept first to check, then
            // submitpackage if needed, but the simplest approach is
            // sendrawtransaction with maxfeerate as a string "0".
            // Bitcoin Core 24+ accepts maxfeerate=0 to skip the fee check.
            let body = serde_json::json!({
                "jsonrpc": "1.0",
                "id": "dark-relay",
                "method": "sendrawtransaction",
                "params": [tx_hex, "0.00000000"]
            });
            match self.client.post(rpc_url).json(&body).send().await {
                Ok(resp) => {
                    let text = resp.text().await.unwrap_or_default();
                    if text.contains("error")
                        && !text.contains("already in block chain")
                        && !text.contains("already known")
                    {
                        tracing::debug!(response = %text.chars().take(200).collect::<String>(),
                            "broadcast_raw_tx: RPC response");
                    } else {
                        tracing::info!("broadcast_raw_tx: tree TX relayed to Bitcoin Core via RPC");
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "broadcast_raw_tx: RPC request failed");
                }
            }
        }
        Ok(())
    }

    fn block_notification_channel(&self) -> broadcast::Receiver<dark_core::ports::NewBlockEvent> {
        self.block_sender.subscribe()
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

    /// A mempool-only spender must NOT be reported as spent — otherwise the
    /// fraud detector would race to broadcast forfeit txs against an
    /// unconfirmed (and potentially RBF-able) spend of the commitment
    /// output.
    #[tokio::test]
    async fn test_is_output_spent_mempool_only_returns_false() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abc123";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"def456","vin":0,"status":{"confirmed":false}}"#)
            .create_async()
            .await;

        let scanner = EsploraScanner::new(&server.url(), 30);
        assert!(!scanner.is_output_spent(txid, 0).await.unwrap());

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
