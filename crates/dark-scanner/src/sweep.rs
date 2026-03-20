//! Esplora-based sweep service for reclaiming expired VTXO outputs.
//!
//! Implements [`SweepService`] by querying an Esplora HTTP API to identify
//! VTXO outputs that have passed their CSV timelock and are eligible for
//! sweeping back to the ASP wallet.

use async_trait::async_trait;
use tracing::{debug, info, warn};

use dark_core::error::{ArkError, ArkResult};
use dark_core::ports::{SweepResult, SweepService};

/// An output identified as sweepable (past its CSV timelock).
#[derive(Debug, Clone)]
pub struct SweepableVtxoOutput {
    /// Transaction ID containing the output.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// CSV delay (in blocks) that has elapsed.
    pub csv_delay: u32,
    /// Current chain height when identified.
    pub identified_at_height: u32,
}

/// Esplora outspend response.
#[derive(Debug, serde::Deserialize)]
struct OutspendResponse {
    spent: bool,
}

/// Esplora block status for a transaction.
#[derive(Debug, serde::Deserialize)]
struct TxStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

/// Minimal Esplora transaction response.
#[derive(Debug, serde::Deserialize)]
struct EsploraTxResponse {
    #[allow(dead_code)]
    txid: String,
    status: TxStatus,
}

/// Esplora-based sweep service that identifies expired VTXO outputs.
///
/// Queries the Esplora API to:
/// 1. Get the current chain tip height
/// 2. Check transaction confirmation status and block height
/// 3. Determine if outputs have passed their CSV timelock
/// 4. Log sweepable outputs for future transaction building
///
/// # Note
/// Full sweep transaction building requires `TxBuilder` wiring which is
/// deferred to a follow-up. This implementation identifies and logs
/// sweepable outputs but does not yet build or broadcast sweep transactions.
pub struct EsploraSweepService {
    base_url: String,
    client: reqwest::Client,
}

impl EsploraSweepService {
    /// Create a new Esplora-based sweep service.
    ///
    /// # Arguments
    /// * `base_url` — Esplora API base URL (e.g. `https://blockstream.info/testnet/api`)
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Get the current chain tip height from Esplora.
    async fn tip_height(&self) -> ArkResult<u32> {
        let url = format!("{}/blocks/tip/height", self.base_url);
        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                ArkError::Internal(format!("Esplora tip height request failed: {e}"))
            })?;

        if !resp.status().is_success() {
            return Err(ArkError::Internal(format!(
                "Esplora GET {} returned {}",
                url,
                resp.status()
            )));
        }

        let text = resp
            .text()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to read tip height: {e}")))?;

        text.trim()
            .parse()
            .map_err(|e| ArkError::Internal(format!("Failed to parse tip height '{}': {e}", text)))
    }

    /// Check if a specific output is unspent on-chain.
    async fn is_output_unspent(&self, txid: &str, vout: u32) -> ArkResult<bool> {
        let url = format!("{}/tx/{}/outspend/{}", self.base_url, txid, vout);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora outspend request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(true); // tx not found means output is unspent
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
            .map_err(|e| ArkError::Internal(format!("Failed to parse outspend: {e}")))?;

        Ok(!outspend.spent)
    }

    /// Get the confirmation block height of a transaction.
    async fn get_tx_block_height(&self, txid: &str) -> ArkResult<Option<u32>> {
        let url = format!("{}/tx/{}", self.base_url, txid);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ArkError::Internal(format!("Esplora tx request failed: {e}")))?;

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

        let tx: EsploraTxResponse = resp
            .json()
            .await
            .map_err(|e| ArkError::Internal(format!("Failed to parse tx response: {e}")))?;

        if tx.status.confirmed {
            Ok(tx.status.block_height)
        } else {
            Ok(None)
        }
    }

    /// Check if a VTXO output has passed its CSV timelock and is sweepable.
    ///
    /// Returns `Some(SweepableVtxoOutput)` if the output is:
    /// 1. Confirmed on-chain
    /// 2. Unspent
    /// 3. Past its CSV delay relative to confirmation height
    pub async fn check_sweepable(
        &self,
        txid: &str,
        vout: u32,
        amount: u64,
        csv_delay: u32,
    ) -> ArkResult<Option<SweepableVtxoOutput>> {
        // Check if the output is still unspent
        if !self.is_output_unspent(txid, vout).await? {
            debug!(txid = %txid, vout, "Output already spent, not sweepable");
            return Ok(None);
        }

        // Get the confirmation height of the transaction
        let confirm_height = match self.get_tx_block_height(txid).await? {
            Some(h) => h,
            None => {
                debug!(txid = %txid, "Transaction not confirmed, not sweepable");
                return Ok(None);
            }
        };

        // Get current tip to check if CSV has elapsed
        let current_height = self.tip_height().await?;
        let blocks_since_confirm = current_height.saturating_sub(confirm_height);

        if blocks_since_confirm < csv_delay {
            debug!(
                txid = %txid,
                vout,
                blocks_since_confirm,
                csv_delay,
                "CSV timelock not yet elapsed"
            );
            return Ok(None);
        }

        info!(
            txid = %txid,
            vout,
            amount,
            csv_delay,
            blocks_since_confirm,
            "Found sweepable VTXO output"
        );

        Ok(Some(SweepableVtxoOutput {
            txid: txid.to_string(),
            vout,
            amount,
            csv_delay,
            identified_at_height: current_height,
        }))
    }
}

#[async_trait]
impl SweepService for EsploraSweepService {
    async fn sweep_expired_vtxos(&self, current_height: u32) -> ArkResult<SweepResult> {
        // TODO(#246): full tx building needs TxBuilder wiring.
        //
        // This stub:
        // 1. Logs that a sweep check is being performed
        // 2. Returns an empty result since we don't yet have the VtxoRepository
        //    injected to query for expired VTXOs
        //
        // Full implementation would:
        // - Query VtxoRepository for expired VTXOs (expires_at < now)
        // - For each, call check_sweepable() to verify on-chain state
        // - Build sweep transactions via TxBuilder
        // - Broadcast via WalletService

        info!(
            current_height,
            "EsploraSweepService: checking for expired VTXOs to sweep"
        );

        warn!(
            "EsploraSweepService: sweep_expired_vtxos is a stub — \
             full tx building needs TxBuilder wiring (see #246)"
        );

        Ok(SweepResult::default())
    }

    async fn sweep_connectors(&self, round_id: &str) -> ArkResult<SweepResult> {
        // TODO(#246): full connector sweep needs TxBuilder + RoundRepository wiring.
        //
        // Full implementation would:
        // - Load the round's VTXO tree from RoundRepository
        // - Call TxBuilder::get_sweepable_batch_outputs() for the tree
        // - Check on-chain status via Esplora
        // - Build and broadcast sweep tx

        info!(
            round_id = %round_id,
            "EsploraSweepService: checking connectors for sweep"
        );

        warn!(
            round_id = %round_id,
            "EsploraSweepService: sweep_connectors is a stub — \
             full tx building needs TxBuilder wiring (see #246)"
        );

        Ok(SweepResult::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sweep_expired_vtxos_stub_returns_empty() {
        let mut server = mockito::Server::new_async().await;

        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.sweep_expired_vtxos(100000).await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_connectors_stub_returns_empty() {
        let service = EsploraSweepService::new("http://localhost:3000");
        let result = service.sweep_connectors("round-123").await.unwrap();

        assert_eq!(result.vtxos_swept, 0);
        assert_eq!(result.sats_recovered, 0);
        assert!(result.tx_ids.is_empty());
    }

    #[tokio::test]
    async fn test_check_sweepable_output_past_csv() {
        let mut server = mockito::Server::new_async().await;
        let txid = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";

        // Output is unspent
        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Transaction confirmed at height 99_000
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99000}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Current tip is 100_000 (1000 blocks later)
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_some(),
            "Output should be sweepable (1000 > 144 CSV)"
        );
        let output = result.unwrap();
        assert_eq!(output.txid, txid);
        assert_eq!(output.amount, 50_000);
        assert_eq!(output.csv_delay, 144);
    }

    #[tokio::test]
    async fn test_check_sweepable_csv_not_elapsed() {
        let mut server = mockito::Server::new_async().await;
        let txid = "1122334455667788112233445566778811223344556677881122334455667788";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":false}"#)
            .create_async()
            .await;

        // Confirmed at 99_900
        let _tx_mock = server
            .mock("GET", format!("/tx/{}", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{"txid":"{}","status":{{"confirmed":true,"block_height":99900}}}}"#,
                txid
            ))
            .create_async()
            .await;

        // Tip at 100_000 → only 100 blocks elapsed, CSV=144
        let _tip_mock = server
            .mock("GET", "/blocks/tip/height")
            .with_status(200)
            .with_body("100000")
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(
            result.is_none(),
            "CSV not elapsed — should not be sweepable"
        );
    }

    #[tokio::test]
    async fn test_check_sweepable_already_spent() {
        let mut server = mockito::Server::new_async().await;
        let txid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let _outspend_mock = server
            .mock("GET", format!("/tx/{}/outspend/0", txid).as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"spent":true,"txid":"spending_tx"}"#)
            .create_async()
            .await;

        let service = EsploraSweepService::new(&server.url());
        let result = service.check_sweepable(txid, 0, 50_000, 144).await.unwrap();

        assert!(result.is_none(), "Already spent — not sweepable");
    }
}
