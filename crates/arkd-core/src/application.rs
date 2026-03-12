//! Application services — aligned with Go arkd's `application.Service`

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::domain::{
    Intent, Round, Vtxo, VtxoOutpoint, DEFAULT_MAX_INTENTS, DEFAULT_MIN_INTENTS,
    DEFAULT_SESSION_DURATION_SECS, DEFAULT_UNILATERAL_EXIT_DELAY, DEFAULT_VTXO_EXPIRY_SECS,
    MIN_VTXO_AMOUNT_SATS,
};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    ArkEvent, CacheService, EventPublisher, SignerService, TxBuilder, VtxoRepository, WalletService,
};

/// ASP configuration
#[derive(Debug, Clone)]
pub struct ArkConfig {
    /// VTXO tree expiry (seconds, default: 7 days)
    pub vtxo_expiry_secs: i64,
    /// Session duration (seconds)
    pub session_duration_secs: u64,
    /// Unilateral exit delay (blocks)
    pub unilateral_exit_delay: u32,
    /// Min intents per round
    pub min_intents: u32,
    /// Max intents per round
    pub max_intents: u32,
    /// Min VTXO amount (sats)
    pub min_vtxo_amount_sats: u64,
    /// Max VTXO amount (sats)
    pub max_vtxo_amount_sats: u64,
    /// Network name
    pub network: String,
}

impl Default for ArkConfig {
    fn default() -> Self {
        Self {
            vtxo_expiry_secs: DEFAULT_VTXO_EXPIRY_SECS,
            session_duration_secs: DEFAULT_SESSION_DURATION_SECS,
            unilateral_exit_delay: DEFAULT_UNILATERAL_EXIT_DELAY,
            min_intents: DEFAULT_MIN_INTENTS,
            max_intents: DEFAULT_MAX_INTENTS,
            min_vtxo_amount_sats: MIN_VTXO_AMOUNT_SATS,
            max_vtxo_amount_sats: 2_100_000_000_000_000,
            network: "regtest".to_string(),
        }
    }
}

/// Main Ark service
pub struct ArkService {
    wallet: Arc<dyn WalletService>,
    signer: Arc<dyn SignerService>,
    vtxo_repo: Arc<dyn VtxoRepository>,
    #[allow(dead_code)]
    tx_builder: Arc<dyn TxBuilder>,
    #[allow(dead_code)]
    cache: Arc<dyn CacheService>,
    events: Arc<dyn EventPublisher>,
    config: ArkConfig,
    current_round: RwLock<Option<Round>>,
}

impl ArkService {
    /// Create a new Ark service
    pub fn new(
        wallet: Arc<dyn WalletService>,
        signer: Arc<dyn SignerService>,
        vtxo_repo: Arc<dyn VtxoRepository>,
        tx_builder: Arc<dyn TxBuilder>,
        cache: Arc<dyn CacheService>,
        events: Arc<dyn EventPublisher>,
        config: ArkConfig,
    ) -> Self {
        Self {
            wallet,
            signer,
            vtxo_repo,
            tx_builder,
            cache,
            events,
            config,
            current_round: RwLock::new(None),
        }
    }

    /// Get config
    pub fn config(&self) -> &ArkConfig {
        &self.config
    }

    /// Get service info
    pub async fn get_info(&self) -> ArkResult<ServiceInfo> {
        let signer_pubkey = self.signer.get_pubkey().await?;
        let forfeit_pubkey = self.wallet.get_forfeit_pubkey().await?;
        let dust = self.wallet.get_dust_amount().await?;
        Ok(ServiceInfo {
            signer_pubkey: signer_pubkey.to_string(),
            forfeit_pubkey: forfeit_pubkey.to_string(),
            unilateral_exit_delay: self.config.unilateral_exit_delay as i64,
            session_duration: self.config.session_duration_secs as i64,
            network: self.config.network.clone(),
            dust,
            vtxo_min_amount: self.config.min_vtxo_amount_sats as i64,
            vtxo_max_amount: self.config.max_vtxo_amount_sats as i64,
        })
    }

    /// Start a new round
    #[instrument(skip(self))]
    pub async fn start_round(&self) -> ArkResult<Round> {
        if let Some(round) = self.current_round.read().await.as_ref() {
            if !round.is_ended() {
                return Err(ArkError::Internal("Round already active".to_string()));
            }
        }
        let mut round = Round::new();
        round.start_registration().map_err(ArkError::Internal)?;
        info!(round_id = %round.id, "Starting new round");
        *self.current_round.write().await = Some(round.clone());
        self.events
            .publish_event(ArkEvent::RoundStarted {
                round_id: round.id.clone(),
                timestamp: round.starting_timestamp,
            })
            .await?;
        Ok(round)
    }

    /// Register an intent
    #[instrument(skip(self, intent))]
    pub async fn register_intent(&self, intent: Intent) -> ArkResult<String> {
        let mut guard = self.current_round.write().await;
        let round = guard
            .as_mut()
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;
        for input in &intent.inputs {
            if input.amount < self.config.min_vtxo_amount_sats {
                return Err(ArkError::AmountTooSmall {
                    amount: input.amount,
                    minimum: self.config.min_vtxo_amount_sats,
                });
            }
        }
        let id = intent.id.clone();
        round.register_intent(intent).map_err(ArkError::Internal)?;
        info!(intent_id = %id, "Intent registered");
        Ok(id)
    }

    /// Get VTXOs for a pubkey
    pub async fn get_vtxos_for_pubkey(&self, pubkey: &str) -> ArkResult<(Vec<Vtxo>, Vec<Vtxo>)> {
        self.vtxo_repo.get_all_vtxos_for_pubkey(pubkey).await
    }

    /// Get VTXOs by outpoints
    pub async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>> {
        self.vtxo_repo.get_vtxos(outpoints).await
    }
}

/// Service info
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceInfo {
    /// Signer pubkey
    pub signer_pubkey: String,
    /// Forfeit pubkey
    pub forfeit_pubkey: String,
    /// Exit delay
    pub unilateral_exit_delay: i64,
    /// Session duration
    pub session_duration: i64,
    /// Network
    pub network: String,
    /// Dust
    pub dust: u64,
    /// Min VTXO amount
    pub vtxo_min_amount: i64,
    /// Max VTXO amount
    pub vtxo_max_amount: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ArkConfig::default();
        assert!(config.vtxo_expiry_secs > 0);
        assert!(config.max_intents > config.min_intents);
        assert!(config.min_vtxo_amount_sats >= 546);
    }
}
