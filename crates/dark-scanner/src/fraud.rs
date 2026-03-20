//! Esplora-based fraud detection for on-chain VTXO double-spend monitoring.
//!
//! Implements [`FraudDetector`] by querying an Esplora HTTP API to check
//! whether VTXO outpoints have been spent on-chain, indicating a potential
//! double-spend or unilateral exit that requires forfeit tx broadcast.

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use dark_core::domain::VtxoOutpoint;
use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::FraudDetector;

/// Esplora-based fraud detector that checks on-chain VTXO spends.
///
/// When a VTXO outpoint is found to be spent on-chain (via the Esplora
/// `GET /tx/{txid}/outspend/{vout}` endpoint), this indicates either a
/// unilateral exit or a double-spend attempt. The detector queues the
/// corresponding forfeit transaction for broadcast.
pub struct EsploraFraudDetector {
    base_url: String,
    client: reqwest::Client,
    /// Forfeit transactions queued for broadcast when fraud is detected.
    pending_forfeit_txs: RwLock<Vec<PendingForfeit>>,
}

/// A forfeit transaction pending broadcast.
#[derive(Debug, Clone)]
pub struct PendingForfeit {
    /// The VTXO that was double-spent.
    pub vtxo_id: String,
    /// The raw forfeit transaction hex to broadcast.
    pub forfeit_tx_hex: String,
}

/// Esplora outspend response for a specific output.
#[derive(Debug, serde::Deserialize)]
struct OutspendResponse {
    spent: bool,
    #[serde(default)]
    txid: Option<String>,
}

impl EsploraFraudDetector {
    /// Create a new Esplora-based fraud detector.
    ///
    /// # Arguments
    /// * `base_url` — Esplora API base URL (e.g. `https://blockstream.info/testnet/api`)
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            pending_forfeit_txs: RwLock::new(Vec::new()),
        }
    }

    /// Check if a VTXO outpoint has been spent on-chain via Esplora.
    ///
    /// Queries `GET /tx/{txid}/outspend/{vout}` and returns `true` if the
    /// output has been spent in a confirmed or unconfirmed transaction.
    pub async fn check_vtxo_spent(&self, outpoint: &VtxoOutpoint) -> ArkResult<bool> {
        let url = format!(
            "{}/tx/{}/outspend/{}",
            self.base_url, outpoint.txid, outpoint.vout
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora outspend request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            // Transaction not found on-chain — VTXO not spent
            return Ok(false);
        }

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let outspend: OutspendResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse outspend response: {e}")))?;

        if outspend.spent {
            debug!(
                txid = %outpoint.txid,
                vout = outpoint.vout,
                spending_txid = ?outspend.txid,
                "VTXO outpoint spent on-chain"
            );
        }

        Ok(outspend.spent)
    }

    /// Get all pending forfeit transactions queued for broadcast.
    pub async fn pending_forfeits(&self) -> Vec<PendingForfeit> {
        self.pending_forfeit_txs.read().await.clone()
    }

    /// Drain and return all pending forfeit transactions.
    pub async fn drain_pending_forfeits(&self) -> Vec<PendingForfeit> {
        let mut guard = self.pending_forfeit_txs.write().await;
        std::mem::take(&mut *guard)
    }
}

#[async_trait]
impl FraudDetector for EsploraFraudDetector {
    async fn detect_double_spend(&self, vtxo_id: &str, _round_id: &str) -> ArkResult<bool> {
        // Parse vtxo_id as "txid:vout"
        let parts: Vec<&str> = vtxo_id.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(ArkError::Internal(format!(
                "Invalid vtxo_id format '{}', expected 'txid:vout'",
                vtxo_id
            )));
        }
        let vout: u32 = parts[1].parse().map_err(|e| {
            ArkError::Internal(format!("Invalid vout in vtxo_id '{}': {}", vtxo_id, e))
        })?;

        let outpoint = VtxoOutpoint::new(parts[0].to_string(), vout);
        let spent = self.check_vtxo_spent(&outpoint).await?;

        if spent {
            info!(
                vtxo_id = %vtxo_id,
                "Double-spend detected: VTXO already spent on-chain"
            );
        }

        Ok(spent)
    }

    async fn react_to_fraud(&self, vtxo_id: &str, forfeit_tx_hex: &str) -> ArkResult<()> {
        warn!(
            vtxo_id = %vtxo_id,
            "Queuing forfeit tx for broadcast (fraud detected)"
        );

        self.pending_forfeit_txs.write().await.push(PendingForfeit {
            vtxo_id: vtxo_id.to_string(),
            forfeit_tx_hex: forfeit_tx_hex.to_string(),
        });

        // TODO(#246): Actually broadcast the forfeit tx via the wallet service.
        // For now we queue it; the round loop or a background task should
        // drain pending_forfeit_txs and call wallet.broadcast_transaction().

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_esplora_fraud_detector_spent() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"spending_tx_123"}"#)
            .create_async()
            .await;

        let detector = EsploraFraudDetector::new(&server.url());
        let outpoint = VtxoOutpoint::new(txid.to_string(), 0);
        assert!(detector.check_vtxo_spent(&outpoint).await.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_esplora_fraud_detector_not_spent() {
        let mut server = mockito::Server::new_async().await;
        let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/1", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        let detector = EsploraFraudDetector::new(&server.url());
        let outpoint = VtxoOutpoint::new(txid.to_string(), 1);
        assert!(!detector.check_vtxo_spent(&outpoint).await.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_detect_double_spend_trait_method() {
        let mut server = mockito::Server::new_async().await;
        let txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let mock = server
            .mock("GET", format!("/tx/{}/outspend/2", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"fraud_tx_456"}"#)
            .create_async()
            .await;

        let detector = EsploraFraudDetector::new(&server.url());
        let vtxo_id = format!("{}:2", txid);
        let result = detector
            .detect_double_spend(&vtxo_id, "round-1")
            .await
            .unwrap();
        assert!(result, "Should detect double-spend");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_react_to_fraud_queues_forfeit() {
        let detector = EsploraFraudDetector::new("http://localhost:3000");

        assert!(detector.pending_forfeits().await.is_empty());

        detector
            .react_to_fraud("vtxo_123:0", "deadbeef_forfeit_hex")
            .await
            .unwrap();

        let pending = detector.pending_forfeits().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].vtxo_id, "vtxo_123:0");
        assert_eq!(pending[0].forfeit_tx_hex, "deadbeef_forfeit_hex");
    }

    #[tokio::test]
    async fn test_drain_pending_forfeits() {
        let detector = EsploraFraudDetector::new("http://localhost:3000");

        detector.react_to_fraud("vtxo_a:0", "hex_a").await.unwrap();
        detector.react_to_fraud("vtxo_b:1", "hex_b").await.unwrap();

        let drained = detector.drain_pending_forfeits().await;
        assert_eq!(drained.len(), 2);
        assert!(detector.pending_forfeits().await.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_vtxo_id_format() {
        let detector = EsploraFraudDetector::new("http://localhost:3000");
        let result = detector
            .detect_double_spend("invalid_no_colon", "round-1")
            .await;
        assert!(result.is_err());
    }
}
