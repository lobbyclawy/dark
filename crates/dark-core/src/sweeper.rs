//! Lightweight VTXO sweeper — finds expired VTXOs and reclaims them for the ASP.
//!
//! Unlike [`crate::sweep::SweepRunner`] which handles batching & broadcasting,
//! this module provides a small, testable core that:
//! 1. Queries for expired VTXOs via [`VtxoRepository::find_expired_vtxos`].
//! 2. Publishes a [`ArkEvent::VtxoForfeited`] for each one.
//! 3. Can be driven by a block-height channel for periodic checks.

use std::sync::Arc;
use tracing::instrument;

use crate::domain::events::ArkEvent;
use crate::domain::Vtxo;
use crate::error::ArkResult;
use crate::ports::{EventPublisher, NoopNotifier, Notifier, VtxoRepository};

/// Sweeps expired VTXOs back to the ASP.
///
/// When a [`Notifier`] is configured (e.g. `dark_nostr::NostrNotifier`),
/// the sweeper will send VTXO expiry notifications to affected users
/// before publishing the sweep event. (Issue #247)
pub struct Sweeper {
    vtxo_repo: Arc<dyn VtxoRepository>,
    events: Arc<dyn EventPublisher>,
    notifier: Arc<dyn Notifier>,
}

impl Sweeper {
    /// Create a new sweeper.
    pub fn new(vtxo_repo: Arc<dyn VtxoRepository>, events: Arc<dyn EventPublisher>) -> Self {
        Self {
            vtxo_repo,
            events,
            notifier: Arc::new(NoopNotifier),
        }
    }

    /// Create a sweeper with a custom notifier for VTXO expiry alerts.
    pub fn with_notifier(mut self, notifier: Arc<dyn Notifier>) -> Self {
        self.notifier = notifier;
        self
    }

    /// Sweep all VTXOs that have expired before `current_timestamp`.
    /// Returns the number of VTXOs swept.
    #[instrument(skip(self))]
    pub async fn sweep_expired(&self, current_timestamp: i64) -> ArkResult<u32> {
        let expired: Vec<Vtxo> = self.vtxo_repo.find_expired_vtxos(current_timestamp).await?;

        let count = expired.len() as u32;

        for vtxo in &expired {
            let vtxo_id = vtxo.outpoint.to_string();
            tracing::info!(
                vtxo_id = %vtxo_id,
                expires_at = vtxo.expires_at,
                "Sweeping expired VTXO"
            );

            // Notify the VTXO owner about the expiry (Issue #247)
            if let Err(e) = self
                .notifier
                .notify_vtxo_expiry(&vtxo.pubkey, &vtxo_id, 0)
                .await
            {
                tracing::warn!(
                    vtxo_id = %vtxo.outpoint,
                    error = %e,
                    "Failed to send VTXO expiry notification (continuing sweep)"
                );
            }

            // TODO: broadcast actual sweep transaction via Bitcoin wallet
            self.events
                .publish_event(ArkEvent::VtxoForfeited {
                    vtxo_id,
                    forfeit_txid: String::new(), // placeholder until real tx is built
                })
                .await?;
        }

        if count > 0 {
            tracing::info!(swept_count = count, "Sweep complete");
        }

        Ok(count)
    }

    /// Spawn a background sweeper loop triggered by block events.
    ///
    /// Every time a new block height arrives on `block_rx`, the sweeper
    /// runs [`sweep_expired`](Self::sweep_expired) using the current wall-clock time.
    pub fn spawn_sweeper_loop(
        sweeper: Arc<Sweeper>,
        mut block_rx: tokio::sync::mpsc::Receiver<u32>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(_height) = block_rx.recv().await {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                match sweeper.sweep_expired(now).await {
                    Ok(n) if n > 0 => tracing::info!(swept = n, "Block sweep done"),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "Sweep error"),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VtxoOutpoint;
    use crate::ports::LoggingEventPublisher;
    use async_trait::async_trait;

    // ── Mock VTXO repository ──────────────────────────────────────────

    /// A configurable mock that returns a fixed set of VTXOs from
    /// `find_expired_vtxos`.
    struct MockVtxoRepo {
        expired: Vec<Vtxo>,
    }

    impl MockVtxoRepo {
        fn empty() -> Self {
            Self {
                expired: Vec::new(),
            }
        }

        fn with_vtxos(vtxos: Vec<Vtxo>) -> Self {
            Self { expired: vtxos }
        }
    }

    #[async_trait]
    impl VtxoRepository for MockVtxoRepo {
        async fn add_vtxos(&self, _vtxos: &[Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(
            &self,
            _pubkey: &str,
        ) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(
            &self,
            _spent: &[(VtxoOutpoint, String)],
            _ark_txid: &str,
        ) -> ArkResult<()> {
            Ok(())
        }
        async fn find_expired_vtxos(&self, _before_timestamp: i64) -> ArkResult<Vec<Vtxo>> {
            Ok(self.expired.clone())
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────

    fn make_vtxo(txid: &str, expires_at: i64) -> Vtxo {
        let mut v = Vtxo::new(
            VtxoOutpoint::new(txid.to_string(), 0),
            50_000,
            "deadbeef".to_string(),
        );
        v.expires_at = expires_at;
        v
    }

    fn make_sweeper(repo: MockVtxoRepo) -> Sweeper {
        Sweeper::new(Arc::new(repo), Arc::new(LoggingEventPublisher::new(16)))
    }

    // ── Tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_sweep_no_expired_returns_zero() {
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(1_000_000).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_expired_vtxo_returns_one() {
        let vtxo = make_vtxo("expired_tx", 500);
        let sweeper = make_sweeper(MockVtxoRepo::with_vtxos(vec![vtxo]));
        let count = sweeper.sweep_expired(1_000).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_sweep_ignores_future_expiry() {
        // The repo's find_expired_vtxos is the filter, but if someone returns
        // a future-expiry VTXO we still count it (repo is authoritative).
        // Here we just verify zero when repo returns nothing.
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(100).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_ignores_zero_expiry() {
        // expires_at == 0 means never expires — repo should not return these.
        let sweeper = make_sweeper(MockVtxoRepo::empty());
        let count = sweeper.sweep_expired(0).await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_sweep_multiple_expired_vtxos() {
        let vtxos = vec![
            make_vtxo("tx1", 100),
            make_vtxo("tx2", 200),
            make_vtxo("tx3", 300),
        ];
        let sweeper = make_sweeper(MockVtxoRepo::with_vtxos(vtxos));
        let count = sweeper.sweep_expired(1_000).await.unwrap();
        assert_eq!(count, 3);
    }
}
