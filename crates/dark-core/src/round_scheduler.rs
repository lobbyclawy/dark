//! Round Scheduler - Periodic round creation and lifecycle management
//!
//! See Go: `github.com/ark-network/ark/internal/core/application/scheduler.go`

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};

use crate::domain::{Round, RoundStage};
use crate::error::{ArkError, ArkResult};
use crate::ports::{ArkEvent, EventPublisher, RoundRepository, WalletService};

/// Round scheduler configuration
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Round interval (time between rounds)
    pub round_interval: Duration,
    /// Registration duration within a round
    pub registration_duration: Duration,
    /// Finalization timeout
    pub finalization_timeout: Duration,
    /// Minimum intents to proceed with finalization
    pub min_intents: u32,
    /// Maximum intents per round
    pub max_intents: u32,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            round_interval: Duration::from_secs(10),
            registration_duration: Duration::from_secs(5),
            finalization_timeout: Duration::from_secs(30),
            min_intents: 1,
            max_intents: 128,
        }
    }
}

/// Commands that can be sent to the scheduler
#[derive(Debug, Clone)]
pub enum SchedulerCommand {
    /// Start the scheduler
    Start,
    /// Stop the scheduler
    Stop,
    /// Force start a new round immediately
    ForceNewRound,
    /// Trigger finalization of current round
    TriggerFinalization,
}

/// Scheduler state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerState {
    /// Scheduler is idle (not running)
    Idle,
    /// Waiting for the next round to start
    WaitingForRound,
    /// Registration stage is active
    Registration,
    /// Finalization stage is active
    Finalization,
    /// Stopping
    Stopping,
}

/// Round scheduler service
///
/// Manages the round lifecycle:
/// 1. Creates new rounds at regular intervals
/// 2. Manages registration stage timing
/// 3. Triggers finalization when registration ends
/// 4. Handles round failures and retries
pub struct RoundScheduler {
    config: SchedulerConfig,
    state: Arc<RwLock<SchedulerState>>,
    current_round: Arc<RwLock<Option<Round>>>,
    round_repo: Arc<dyn RoundRepository>,
    events: Arc<dyn EventPublisher>,
    wallet: Arc<dyn WalletService>,
    command_tx: mpsc::Sender<SchedulerCommand>,
    command_rx: Arc<RwLock<Option<mpsc::Receiver<SchedulerCommand>>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl RoundScheduler {
    /// Create a new round scheduler
    pub fn new(
        config: SchedulerConfig,
        round_repo: Arc<dyn RoundRepository>,
        events: Arc<dyn EventPublisher>,
        wallet: Arc<dyn WalletService>,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::channel(32);
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            state: Arc::new(RwLock::new(SchedulerState::Idle)),
            current_round: Arc::new(RwLock::new(None)),
            round_repo,
            events,
            wallet,
            command_tx,
            command_rx: Arc::new(RwLock::new(Some(command_rx))),
            shutdown_tx,
        }
    }

    /// Get command sender for controlling the scheduler
    pub fn command_sender(&self) -> mpsc::Sender<SchedulerCommand> {
        self.command_tx.clone()
    }

    /// Get current scheduler state
    pub async fn state(&self) -> SchedulerState {
        *self.state.read().await
    }

    /// Get current round if any
    pub async fn current_round(&self) -> Option<Round> {
        self.current_round.read().await.clone()
    }

    /// Start the scheduler loop
    #[instrument(skip(self))]
    pub async fn run(&self) -> ArkResult<()> {
        let mut command_rx = self
            .command_rx
            .write()
            .await
            .take()
            .ok_or_else(|| ArkError::Internal("Scheduler already running".to_string()))?;

        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut round_timer = interval(self.config.round_interval);

        // Start in waiting state
        *self.state.write().await = SchedulerState::WaitingForRound;
        info!(
            "Round scheduler started (interval: {:?})",
            self.config.round_interval
        );

        loop {
            tokio::select! {
                _ = round_timer.tick() => {
                    if *self.state.read().await == SchedulerState::WaitingForRound {
                        if let Err(e) = self.start_new_round().await {
                            error!("Failed to start new round: {e}");
                        }
                    }
                }

                Some(cmd) = command_rx.recv() => {
                    match cmd {
                        SchedulerCommand::Start => {
                            *self.state.write().await = SchedulerState::WaitingForRound;
                            info!("Scheduler started");
                        }
                        SchedulerCommand::Stop => {
                            *self.state.write().await = SchedulerState::Stopping;
                            info!("Scheduler stopping");
                            break;
                        }
                        SchedulerCommand::ForceNewRound => {
                            if let Err(e) = self.start_new_round().await {
                                error!("Failed to force new round: {e}");
                            }
                        }
                        SchedulerCommand::TriggerFinalization => {
                            if let Err(e) = self.finalize_round().await {
                                error!("Failed to trigger finalization: {e}");
                            }
                        }
                    }
                }

                _ = shutdown_rx.recv() => {
                    info!("Scheduler received shutdown signal");
                    break;
                }
            }
        }

        *self.state.write().await = SchedulerState::Idle;
        info!("Round scheduler stopped");
        Ok(())
    }

    /// Shutdown the scheduler
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Start a new round
    #[instrument(skip(self))]
    async fn start_new_round(&self) -> ArkResult<Round> {
        // Check if there's already an active round
        {
            let current = self.current_round.read().await;
            if let Some(round) = current.as_ref() {
                if !round.is_ended() {
                    return Err(ArkError::Internal(
                        "Cannot start new round while one is active".to_string(),
                    ));
                }
            }
        }

        // Create new round
        let mut round = Round::new();
        round.start_registration().map_err(ArkError::Internal)?;

        // Persist round
        self.round_repo.add_or_update_round(&round).await?;

        // Update state
        *self.state.write().await = SchedulerState::Registration;
        *self.current_round.write().await = Some(round.clone());

        // Publish event
        self.events
            .publish_event(ArkEvent::RoundStarted {
                round_id: round.id.clone(),
                timestamp: round.starting_timestamp,
            })
            .await?;

        info!(round_id = %round.id, "New round started - registration open");

        // Schedule registration end
        let registration_duration = self.config.registration_duration;
        let state = self.state.clone();
        let current_round = self.current_round.clone();
        let round_repo = self.round_repo.clone();
        let events = self.events.clone();
        let finalization_timeout = self.config.finalization_timeout;
        let min_intents = self.config.min_intents;
        let wallet = self.wallet.clone();

        let round_id = round.id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(registration_duration).await;

            // Transition to finalization
            if let Err(e) = Self::transition_to_finalization(
                &state,
                &current_round,
                &round_repo,
                &events,
                &wallet,
                min_intents,
                finalization_timeout,
            )
            .await
            {
                error!(round_id = %round_id, "Failed to transition to finalization: {e}");
            }
        });

        Ok(round)
    }

    /// Transition from registration to finalization
    async fn transition_to_finalization(
        state: &Arc<RwLock<SchedulerState>>,
        current_round: &Arc<RwLock<Option<Round>>>,
        round_repo: &Arc<dyn RoundRepository>,
        events: &Arc<dyn EventPublisher>,
        wallet: &Arc<dyn WalletService>,
        min_intents: u32,
        finalization_timeout: Duration,
    ) -> ArkResult<()> {
        let mut guard = current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        // Check minimum intents
        if (round.intent_count() as u32) < min_intents {
            info!(
                round_id = %round.id,
                intents = round.intent_count(),
                min = min_intents,
                "Not enough intents, skipping round"
            );
            round.fail("Not enough participants".to_string());
            round_repo.add_or_update_round(round).await?;
            *state.write().await = SchedulerState::WaitingForRound;
            return Ok(());
        }

        // Transition to finalization stage
        round.start_finalization().map_err(ArkError::Internal)?;
        round_repo.add_or_update_round(round).await?;
        *state.write().await = SchedulerState::Finalization;

        info!(
            round_id = %round.id,
            intents = round.intent_count(),
            "Round transitioning to finalization"
        );

        // Schedule finalization timeout
        let round_id = round.id.clone();
        let state_clone = state.clone();
        let current_round_clone = current_round.clone();
        let round_repo_clone = round_repo.clone();
        let events_clone = events.clone();
        let _wallet_clone = wallet.clone();

        tokio::spawn(async move {
            tokio::time::sleep(finalization_timeout).await;

            // Check if still in finalization (not already completed)
            let current_state = *state_clone.read().await;
            if current_state == SchedulerState::Finalization {
                // Timeout - fail the round
                if let Some(round) = current_round_clone.write().await.as_mut() {
                    if round.stage.code == RoundStage::Finalization && !round.is_ended() {
                        warn!(round_id = %round_id, "Round finalization timed out");
                        round.fail("Finalization timeout".to_string());
                        let _ = round_repo_clone.add_or_update_round(round).await;
                        let _ = events_clone
                            .publish_event(ArkEvent::RoundFailed {
                                round_id: round_id.clone(),
                                reason: "Finalization timeout".to_string(),
                                timestamp: chrono::Utc::now().timestamp(),
                            })
                            .await;
                    }
                }
                *state_clone.write().await = SchedulerState::WaitingForRound;
            }
        });

        Ok(())
    }

    /// Finalize the current round
    #[instrument(skip(self))]
    async fn finalize_round(&self) -> ArkResult<()> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.stage.code != RoundStage::Finalization {
            return Err(ArkError::Internal(
                "Round not in finalization stage".to_string(),
            ));
        }

        // TODO: Build and broadcast commitment transaction
        // This will be implemented when TxBuilder is connected

        // For now, mark as complete
        round.end_successfully();
        self.round_repo.add_or_update_round(round).await?;

        // Publish event
        self.events
            .publish_event(ArkEvent::RoundFinalized {
                round_id: round.id.clone(),
                commitment_tx: round.commitment_tx.clone(),
                timestamp: round.ending_timestamp,
                vtxo_count: 0, // TODO: populate from round vtxo tree
            })
            .await?;

        info!(round_id = %round.id, "Round finalized successfully");

        *self.state.write().await = SchedulerState::WaitingForRound;
        Ok(())
    }

    /// Register an intent for the current round
    #[instrument(skip(self, intent))]
    pub async fn register_intent(&self, intent: crate::domain::Intent) -> ArkResult<String> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        if round.stage.code != RoundStage::Registration {
            return Err(ArkError::RoundRegistrationClosed(round.id.clone()));
        }

        if round.intent_count() as u32 >= self.config.max_intents {
            return Err(ArkError::RoundFull {
                round_id: round.id.clone(),
                max_intents: self.config.max_intents,
            });
        }

        // Validate proof
        self.validate_intent_proof(&intent).await?;

        let id = intent.id.clone();
        round.register_intent(intent).map_err(ArkError::Internal)?;

        // Persist
        self.round_repo.add_or_update_round(round).await?;

        debug!(intent_id = %id, round_id = %round.id, "Intent registered");
        Ok(id)
    }

    /// Validate an intent's proof
    async fn validate_intent_proof(&self, intent: &crate::domain::Intent) -> ArkResult<()> {
        // Verify the proof is not empty
        if intent.proof.is_empty() {
            return Err(ArkError::InvalidVtxoProof("Empty proof".to_string()));
        }

        // Verify the message is not empty
        if intent.message.is_empty() {
            return Err(ArkError::InvalidVtxoProof("Empty message".to_string()));
        }

        // Verify inputs exist and are spendable
        for input in &intent.inputs {
            if !input.is_spendable() {
                return Err(ArkError::VtxoAlreadySpent(input.outpoint.to_string()));
            }

            // Check VTXO hasn't expired
            let now = chrono::Utc::now().timestamp();
            if input.is_expired_at(now) {
                return Err(ArkError::VtxoExpired {
                    vtxo_id: input.outpoint.to_string(),
                    expires_at: input.expires_at,
                });
            }
        }

        // Verify amounts balance (inputs >= outputs)
        let total_in = intent.total_input_amount();
        let total_out = intent.total_output_amount();
        if total_out > total_in {
            return Err(ArkError::InvalidVtxoProof(format!(
                "Output amount ({total_out}) exceeds input amount ({total_in})"
            )));
        }

        // TODO: Verify cryptographic proof (signature)
        // This requires implementing proper Schnorr signature verification
        // For now, we accept the proof if it passes basic validation

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Intent, Receiver, Vtxo, VtxoOutpoint};
    use async_trait::async_trait;
    use bitcoin::XOnlyPublicKey;

    // Mock implementations for testing
    struct MockRoundRepo {
        rounds: Arc<RwLock<std::collections::HashMap<String, Round>>>,
    }

    impl MockRoundRepo {
        fn new() -> Self {
            Self {
                rounds: Arc::new(RwLock::new(std::collections::HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl RoundRepository for MockRoundRepo {
        async fn add_or_update_round(&self, round: &Round) -> ArkResult<()> {
            self.rounds
                .write()
                .await
                .insert(round.id.clone(), round.clone());
            Ok(())
        }

        async fn get_round_with_id(&self, id: &str) -> ArkResult<Option<Round>> {
            Ok(self.rounds.read().await.get(id).cloned())
        }

        async fn get_round_stats(
            &self,
            _commitment_txid: &str,
        ) -> ArkResult<Option<crate::domain::RoundStats>> {
            Ok(None)
        }

        async fn confirm_intent(&self, _round_id: &str, _intent_id: &str) -> ArkResult<()> {
            Ok(())
        }

        async fn get_pending_confirmations(&self, _round_id: &str) -> ArkResult<Vec<String>> {
            Ok(Vec::new())
        }
    }

    struct MockEventPublisher {
        events: Arc<RwLock<Vec<ArkEvent>>>,
    }

    impl MockEventPublisher {
        fn new() -> Self {
            Self {
                events: Arc::new(RwLock::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl EventPublisher for MockEventPublisher {
        async fn publish_event(&self, event: ArkEvent) -> ArkResult<()> {
            self.events.write().await.push(event);
            Ok(())
        }

        async fn subscribe(&self) -> ArkResult<broadcast::Receiver<ArkEvent>> {
            let (_tx, rx) = broadcast::channel(16);
            Ok(rx)
        }
    }

    struct MockWalletService;

    #[async_trait]
    impl WalletService for MockWalletService {
        async fn status(&self) -> ArkResult<crate::ports::WalletStatus> {
            Ok(crate::ports::WalletStatus {
                initialized: true,
                unlocked: true,
                synced: true,
            })
        }

        async fn get_forfeit_pubkey(&self) -> ArkResult<XOnlyPublicKey> {
            let bytes = [1u8; 32];
            Ok(XOnlyPublicKey::from_slice(&bytes).unwrap())
        }

        async fn derive_connector_address(&self) -> ArkResult<String> {
            Ok("bc1qtest".to_string())
        }

        async fn sign_transaction(
            &self,
            partial_tx: &str,
            _extract_raw: bool,
        ) -> ArkResult<String> {
            Ok(partial_tx.to_string())
        }

        async fn select_utxos(
            &self,
            _amount: u64,
            _confirmed_only: bool,
        ) -> ArkResult<(Vec<crate::ports::TxInput>, u64)> {
            Ok((vec![], 0))
        }

        async fn broadcast_transaction(&self, _txs: Vec<String>) -> ArkResult<String> {
            Ok("txid".to_string())
        }

        async fn fee_rate(&self) -> ArkResult<u64> {
            Ok(10)
        }

        async fn get_current_block_time(&self) -> ArkResult<crate::ports::BlockTimestamp> {
            Ok(crate::ports::BlockTimestamp {
                height: 100,
                timestamp: chrono::Utc::now().timestamp(),
            })
        }

        async fn get_dust_amount(&self) -> ArkResult<u64> {
            Ok(546)
        }

        async fn get_outpoint_status(&self, _outpoint: &VtxoOutpoint) -> ArkResult<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();
        assert!(config.round_interval.as_secs() > 0);
        assert!(config.max_intents > config.min_intents);
    }

    #[tokio::test]
    async fn test_scheduler_creation() {
        let config = SchedulerConfig::default();
        let round_repo = Arc::new(MockRoundRepo::new());
        let events = Arc::new(MockEventPublisher::new());
        let wallet = Arc::new(MockWalletService);

        let scheduler = RoundScheduler::new(config, round_repo, events, wallet);
        assert_eq!(scheduler.state().await, SchedulerState::Idle);
    }

    #[tokio::test]
    async fn test_intent_validation() {
        let config = SchedulerConfig::default();
        let round_repo = Arc::new(MockRoundRepo::new());
        let events = Arc::new(MockEventPublisher::new());
        let wallet = Arc::new(MockWalletService);

        let scheduler = RoundScheduler::new(config, round_repo, events, wallet);

        // Start a round manually for testing
        {
            let mut round = Round::new();
            round.start_registration().unwrap();
            *scheduler.current_round.write().await = Some(round);
            *scheduler.state.write().await = SchedulerState::Registration;
        }

        // Create a valid intent
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("txid123".to_string(), 0),
            100_000,
            "deadbeef".repeat(4),
        );
        let mut intent = Intent::new(
            "proof_txid".to_string(),
            "proof_data".to_string(),
            "message".to_string(),
            vec![vtxo],
        )
        .unwrap();
        intent
            .add_receivers(vec![Receiver::offchain(
                50_000,
                "receiver_pubkey".to_string(),
            )])
            .unwrap();

        let result = scheduler.register_intent(intent).await;
        assert!(result.is_ok());
    }
}
