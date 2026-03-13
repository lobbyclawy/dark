//! Application services — aligned with Go arkd's `application.Service`

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::domain::{
    CollaborativeExitRequest, Exit, ExitSummary, ExitType, Intent, Round, UnilateralExitRequest,
    Vtxo, VtxoOutpoint, DEFAULT_BOARDING_EXIT_DELAY, DEFAULT_MAX_INTENTS, DEFAULT_MAX_TX_WEIGHT,
    DEFAULT_MIN_INTENTS, DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY, DEFAULT_SESSION_DURATION_SECS,
    DEFAULT_UNILATERAL_EXIT_DELAY, DEFAULT_UTXO_MAX_AMOUNT, DEFAULT_UTXO_MIN_AMOUNT,
    DEFAULT_VTXO_EXPIRY_SECS, MIN_VTXO_AMOUNT_SATS,
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
    /// Min UTXO amount for boarding (sats)
    pub utxo_min_amount: u64,
    /// Max UTXO amount for boarding (sats, 0 = boarding disabled)
    pub utxo_max_amount: u64,
    /// CSV delay for public unilateral exits (blocks)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (blocks)
    pub boarding_exit_delay: u32,
    /// Max commitment tx weight
    pub max_tx_weight: u64,
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
            utxo_min_amount: DEFAULT_UTXO_MIN_AMOUNT,
            utxo_max_amount: DEFAULT_UTXO_MAX_AMOUNT,
            public_unilateral_exit_delay: DEFAULT_PUBLIC_UNILATERAL_EXIT_DELAY,
            boarding_exit_delay: DEFAULT_BOARDING_EXIT_DELAY,
            max_tx_weight: DEFAULT_MAX_TX_WEIGHT,
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
    /// Active exits indexed by ID
    /// TODO(#9): Back with SQLite persistence to survive restarts
    exits: RwLock<std::collections::HashMap<uuid::Uuid, Exit>>,
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
            exits: RwLock::new(std::collections::HashMap::new()),
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

        // Derive forfeit address from the forfeit pubkey (P2TR)
        let network = match self.config.network.as_str() {
            "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
            "testnet" => bitcoin::Network::Testnet,
            "signet" => bitcoin::Network::Signet,
            _ => bitcoin::Network::Regtest,
        };
        let forfeit_address = bitcoin::Address::p2tr(
            &bitcoin::secp256k1::Secp256k1::new(),
            forfeit_pubkey,
            None,
            network,
        )
        .to_string();

        // Derive checkpoint tapscript from the signer pubkey (hex-encoded OP_CHECKSIG script)
        let checkpoint_tapscript = format!("20{}ac", signer_pubkey);

        Ok(ServiceInfo {
            signer_pubkey: signer_pubkey.to_string(),
            forfeit_pubkey: forfeit_pubkey.to_string(),
            unilateral_exit_delay: self.config.unilateral_exit_delay as i64,
            session_duration: self.config.session_duration_secs as i64,
            network: self.config.network.clone(),
            dust,
            vtxo_min_amount: self.config.min_vtxo_amount_sats as i64,
            vtxo_max_amount: self.config.max_vtxo_amount_sats as i64,
            forfeit_address,
            checkpoint_tapscript,
            utxo_min_amount: self.config.utxo_min_amount,
            utxo_max_amount: self.config.utxo_max_amount,
            public_unilateral_exit_delay: self.config.public_unilateral_exit_delay,
            boarding_exit_delay: self.config.boarding_exit_delay,
            max_tx_weight: self.config.max_tx_weight,
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

    // ── Exit Mechanisms ─────────────────────────────────────────────

    /// Request a collaborative exit
    ///
    /// The exit will be included in the next round as on-chain outputs.
    #[instrument(skip(self, request))]
    pub async fn request_collaborative_exit(
        &self,
        request: CollaborativeExitRequest,
        requester_pubkey: bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Exit> {
        // Validate VTXOs exist and are spendable
        let vtxos = self.vtxo_repo.get_vtxos(&request.vtxo_ids).await?;
        if vtxos.is_empty() {
            return Err(ArkError::VtxoNotFound(
                "No VTXOs found for exit".to_string(),
            ));
        }

        for vtxo in &vtxos {
            if !vtxo.is_spendable() {
                return Err(ArkError::VtxoAlreadySpent(vtxo.outpoint.to_string()));
            }
        }

        let total_amount: u64 = vtxos.iter().map(|v| v.amount).sum();
        let exit = Exit::collaborative(
            request.vtxo_ids,
            request.destination,
            requester_pubkey,
            bitcoin::Amount::from_sat(total_amount),
        );

        self.exits.write().await.insert(exit.id, exit.clone());
        info!(exit_id = %exit.id, amount = total_amount, "Collaborative exit requested");

        Ok(exit)
    }

    /// Request a unilateral exit
    ///
    /// The user will publish their VTXO tree branch on-chain.
    #[instrument(skip(self, request))]
    pub async fn request_unilateral_exit(
        &self,
        request: UnilateralExitRequest,
        requester_pubkey: bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Exit> {
        // Validate VTXO exists and is spendable
        let vtxos = self
            .vtxo_repo
            .get_vtxos(std::slice::from_ref(&request.vtxo_id))
            .await?;
        let vtxo = vtxos
            .first()
            .ok_or_else(|| ArkError::VtxoNotFound(request.vtxo_id.to_string()))?;

        if !vtxo.is_spendable() {
            return Err(ArkError::VtxoAlreadySpent(vtxo.outpoint.to_string()));
        }

        // Calculate claimable height
        let block_time = self.wallet.get_current_block_time().await?;
        let claimable_height = block_time.height as u32 + self.config.unilateral_exit_delay;

        let exit = Exit::unilateral(
            request.vtxo_id,
            request.destination,
            requester_pubkey,
            bitcoin::Amount::from_sat(vtxo.amount),
            claimable_height,
        );

        self.exits.write().await.insert(exit.id, exit.clone());
        info!(
            exit_id = %exit.id,
            amount = vtxo.amount,
            claimable_height,
            "Unilateral exit requested"
        );

        Ok(exit)
    }

    /// Cancel a pending exit
    #[instrument(skip(self))]
    pub async fn cancel_exit(&self, exit_id: uuid::Uuid) -> ArkResult<()> {
        let mut exits = self.exits.write().await;
        let exit = exits
            .get_mut(&exit_id)
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))?;

        exit.cancel()
            .map_err(|e| ArkError::InvalidExitRequest(e.to_string()))?;

        info!(exit_id = %exit_id, "Exit cancelled");
        Ok(())
    }

    /// Get an exit by ID
    pub async fn get_exit(&self, exit_id: uuid::Uuid) -> ArkResult<Exit> {
        self.exits
            .read()
            .await
            .get(&exit_id)
            .cloned()
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))
    }

    /// Get all exits for a given type
    pub async fn get_exits_by_type(&self, exit_type: ExitType) -> Vec<ExitSummary> {
        self.exits
            .read()
            .await
            .values()
            .filter(|e| e.exit_type == exit_type)
            .map(ExitSummary::from)
            .collect()
    }

    /// Get pending collaborative exits for inclusion in next round
    pub async fn get_pending_collaborative_exits(&self) -> Vec<Exit> {
        self.exits
            .read()
            .await
            .values()
            .filter(|e| {
                e.exit_type == ExitType::Collaborative
                    && e.status == crate::domain::ExitStatus::Pending
            })
            .cloned()
            .collect()
    }

    /// Complete an exit after round finalization or on-chain confirmation
    #[instrument(skip(self))]
    pub async fn complete_exit(&self, exit_id: uuid::Uuid, fee: bitcoin::Amount) -> ArkResult<()> {
        let mut exits = self.exits.write().await;
        let exit = exits
            .get_mut(&exit_id)
            .ok_or_else(|| ArkError::ExitNotFound(exit_id.to_string()))?;

        exit.complete(fee);
        info!(exit_id = %exit_id, "Exit completed");
        Ok(())
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
    /// On-chain address for forfeit outputs
    pub forfeit_address: String,
    /// Tapscript for checkpoint outputs
    pub checkpoint_tapscript: String,
    /// Min UTXO amount for boarding (sats)
    pub utxo_min_amount: u64,
    /// Max UTXO amount for boarding (sats)
    pub utxo_max_amount: u64,
    /// CSV delay for public unilateral exits (blocks)
    pub public_unilateral_exit_delay: u32,
    /// CSV delay for boarding inputs (blocks)
    pub boarding_exit_delay: u32,
    /// Max commitment tx weight
    pub max_tx_weight: u64,
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

    #[test]
    fn test_config_new_field_defaults() {
        let config = ArkConfig::default();
        assert_eq!(config.utxo_min_amount, 1_000);
        assert_eq!(config.utxo_max_amount, 100_000_000);
        assert_eq!(config.public_unilateral_exit_delay, 512);
        assert_eq!(config.boarding_exit_delay, 512);
        assert_eq!(config.max_tx_weight, 400_000);
    }
}
