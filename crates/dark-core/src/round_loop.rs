//! Round loop — consumes scheduler ticks and triggers new rounds.
//!
//! This is the glue between the `TimeScheduler` port and `ArkService::start_round`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::application::ArkService;

/// Spawn a background task that calls `core.start_round()` on every tick.
///
/// Returns a `JoinHandle` so the caller can await or abort the loop.
/// The loop exits cleanly when `tick_rx` is closed (sender dropped).
pub fn spawn_round_loop(core: Arc<ArkService>, mut tick_rx: mpsc::Receiver<()>) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("Round loop started — waiting for scheduler ticks");

        while let Some(()) = tick_rx.recv().await {
            match core.start_round().await {
                Ok(round) => {
                    info!(round_id = %round.id, "Round triggered by scheduler");
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("already active") {
                        // Round still running — skip this tick silently
                    } else {
                        error!("Failed to start round: {e}");
                    }
                }
            }
        }

        info!("Round loop exiting — tick channel closed");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;
    use bitcoin::XOnlyPublicKey;
    use tokio::sync::broadcast;

    use crate::application::ArkConfig;
    use crate::domain::VtxoOutpoint;
    use crate::error::ArkResult;
    use crate::ports::*;

    // ── Minimal mock implementations ────────────────────────────────

    struct StubWallet;
    #[async_trait]
    impl WalletService for StubWallet {
        async fn status(&self) -> ArkResult<WalletStatus> {
            Ok(WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }
        async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok(String::new())
        }
        async fn sign_transaction(&self, p: &str, _: bool) -> ArkResult<String> {
            Ok(p.into())
        }
        async fn select_utxos(&self, _: u64, _: bool) -> ArkResult<(Vec<TxInput>, u64)> {
            Ok((vec![], 0))
        }
        async fn broadcast_transaction(&self, _: Vec<String>) -> ArkResult<String> {
            Ok(String::new())
        }
        async fn fee_rate(&self) -> ArkResult<u64> {
            Ok(1)
        }
        async fn get_current_block_time(&self) -> ArkResult<BlockTimestamp> {
            Ok(BlockTimestamp {
                height: 1,
                timestamp: 0,
            })
        }
        async fn get_dust_amount(&self) -> ArkResult<u64> {
            Ok(546)
        }
        async fn get_outpoint_status(&self, _: &VtxoOutpoint) -> ArkResult<bool> {
            Ok(false)
        }
    }

    struct StubSigner;
    #[async_trait]
    impl SignerService for StubSigner {
        async fn get_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            Ok(XOnlyPublicKey::from_slice(&[1u8; 32]).unwrap())
        }
        async fn sign_transaction(&self, p: &str, _: bool) -> ArkResult<String> {
            Ok(p.into())
        }
    }

    struct StubVtxoRepo;
    #[async_trait]
    impl VtxoRepository for StubVtxoRepo {
        async fn add_vtxos(&self, _: &[crate::domain::Vtxo]) -> ArkResult<()> {
            Ok(())
        }
        async fn get_vtxos(&self, _: &[VtxoOutpoint]) -> ArkResult<Vec<crate::domain::Vtxo>> {
            Ok(vec![])
        }
        async fn get_all_vtxos_for_pubkey(
            &self,
            _: &str,
        ) -> ArkResult<(Vec<crate::domain::Vtxo>, Vec<crate::domain::Vtxo>)> {
            Ok((vec![], vec![]))
        }
        async fn spend_vtxos(&self, _: &[(VtxoOutpoint, String)], _: &str) -> ArkResult<()> {
            Ok(())
        }
    }

    struct StubTxBuilder;
    #[async_trait]
    impl TxBuilder for StubTxBuilder {
        async fn build_commitment_tx(
            &self,
            _: &XOnlyPublicKey,
            _: &[crate::domain::Intent],
            _: &[BoardingInput],
        ) -> ArkResult<CommitmentTxResult> {
            unimplemented!()
        }
        async fn verify_forfeit_txs(
            &self,
            _: &[crate::domain::Vtxo],
            _: &crate::domain::FlatTxTree,
            _: &[String],
        ) -> ArkResult<Vec<ValidForfeitTx>> {
            unimplemented!()
        }
        async fn build_sweep_tx(
            &self,
            _: &[crate::ports::SweepInput],
        ) -> ArkResult<(String, String)> {
            unimplemented!()
        }
        async fn get_sweepable_batch_outputs(
            &self,
            _: &crate::domain::FlatTxTree,
        ) -> ArkResult<Option<crate::ports::SweepableOutput>> {
            unimplemented!()
        }
        async fn finalize_and_extract(&self, _: &str) -> ArkResult<String> {
            unimplemented!()
        }
        async fn verify_vtxo_tapscript_sigs(&self, _: &str, _: bool) -> ArkResult<bool> {
            unimplemented!()
        }
        async fn verify_boarding_tapscript_sigs(
            &self,
            _: &str,
            _: &str,
        ) -> ArkResult<std::collections::HashMap<u32, crate::ports::SignedBoardingInput>> {
            unimplemented!()
        }
    }

    struct StubCache;
    #[async_trait]
    impl CacheService for StubCache {
        async fn set(&self, _: &str, _: &[u8], _: Option<u64>) -> ArkResult<()> {
            Ok(())
        }
        async fn get(&self, _: &str) -> ArkResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn delete(&self, _: &str) -> ArkResult<bool> {
            Ok(false)
        }
    }

    struct CountingEvents {
        count: AtomicU32,
    }
    impl CountingEvents {
        fn new() -> Self {
            Self {
                count: AtomicU32::new(0),
            }
        }
        fn round_started_count(&self) -> u32 {
            self.count.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl EventPublisher for CountingEvents {
        async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
            if matches!(event, ArkEvent::RoundStarted { .. }) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
        async fn subscribe(&self) -> ArkResult<broadcast::Receiver<ArkEvent>> {
            let (_tx, rx) = broadcast::channel(1);
            Ok(rx)
        }
    }

    fn make_core(events: Arc<CountingEvents>) -> Arc<ArkService> {
        Arc::new(ArkService::new(
            Arc::new(StubWallet),
            Arc::new(StubSigner),
            Arc::new(StubVtxoRepo),
            Arc::new(StubTxBuilder),
            Arc::new(StubCache),
            events,
            ArkConfig::default(),
        ))
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn tick_triggers_round() {
        let events = Arc::new(CountingEvents::new());
        let core = make_core(events.clone());
        let (tx, rx) = mpsc::channel(1);

        let handle = spawn_round_loop(core, rx);

        tx.send(()).await.unwrap();
        // Give the loop a moment to process
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(events.round_started_count(), 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn error_does_not_kill_loop() {
        let events = Arc::new(CountingEvents::new());
        let core = make_core(events.clone());
        let (tx, rx) = mpsc::channel(2);

        let handle = spawn_round_loop(core, rx);

        // First tick starts a round (succeeds)
        tx.send(()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Second tick: round already active → error, but loop should survive
        tx.send(()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Loop is still alive — count is still 1 (second call errored)
        assert_eq!(events.round_started_count(), 1);

        drop(tx);
        handle.await.unwrap(); // exits cleanly
    }

    #[tokio::test]
    async fn handle_is_returned_and_joinable() {
        let events = Arc::new(CountingEvents::new());
        let core = make_core(events);
        let (tx, rx) = mpsc::channel(1);

        let handle = spawn_round_loop(core, rx);
        assert!(!handle.is_finished());

        drop(tx);
        let result = handle.await;
        assert!(result.is_ok());
    }
}
