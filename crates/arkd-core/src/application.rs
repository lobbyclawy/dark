//! Application services - Use cases and business logic
//!
//! This module orchestrates domain models and ports to implement
//! the Ark protocol's business logic. It acts as the "use case" layer
//! in clean architecture.
//!
//! # Services
//!
//! - **RoundService**: Manages round lifecycle
//! - **VtxoService**: VTXO creation, transfer, and management
//! - **ExitService**: Handles collaborative and unilateral exits
//!
//! # Example
//!
//! ```rust,ignore
//! use arkd_core::application::ArkService;
//!
//! // Create the main service with dependency injection
//! let service = ArkService::new(
//!     wallet_service,
//!     database_service,
//!     bitcoin_rpc,
//!     cache_service,
//!     event_publisher,
//!     config,
//! );
//!
//! // Start a new round
//! let round = service.start_round().await?;
//! ```

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::domain::{
    Exit, Participant, Round, RoundConfig, RoundStatus, Vtxo, VtxoId, DEFAULT_EXIT_DELTA_BLOCKS,
    DEFAULT_MAX_PARTICIPANTS, DEFAULT_MIN_PARTICIPANTS, DEFAULT_VTXO_EXPIRY_BLOCKS,
    MIN_VTXO_AMOUNT_SATS,
};
use crate::error::{ArkError, ArkResult};
use crate::ports::{
    ArkEvent, BitcoinRpcService, CacheService, DatabaseService, EventPublisher, WalletService,
};

/// Configuration for the Ark service
#[derive(Debug, Clone)]
pub struct ArkConfig {
    /// Minimum participants per round
    pub min_participants: u32,

    /// Maximum participants per round
    pub max_participants: u32,

    /// VTXO lifetime in blocks
    pub vtxo_lifetime_blocks: u32,

    /// Exit delta (timelock) in blocks
    pub exit_delta_blocks: u32,

    /// Minimum VTXO amount in satoshis
    pub min_vtxo_amount_sats: u64,

    /// Registration window duration in seconds
    pub registration_duration_secs: u64,

    /// Signing window duration in seconds
    pub signing_duration_secs: u64,

    /// Whether to auto-start rounds
    pub auto_start_rounds: bool,
}

impl Default for ArkConfig {
    fn default() -> Self {
        Self {
            min_participants: DEFAULT_MIN_PARTICIPANTS,
            max_participants: DEFAULT_MAX_PARTICIPANTS,
            vtxo_lifetime_blocks: DEFAULT_VTXO_EXPIRY_BLOCKS,
            exit_delta_blocks: DEFAULT_EXIT_DELTA_BLOCKS,
            min_vtxo_amount_sats: MIN_VTXO_AMOUNT_SATS,
            registration_duration_secs: 30, // 30 seconds (matches upstream arkd round session)
            signing_duration_secs: 120,     // 2 minutes
            auto_start_rounds: true,
        }
    }
}

/// Main Ark service that coordinates all protocol operations
///
/// This is the entry point for all Ark protocol functionality.
/// It uses dependency injection for all external services.
pub struct ArkService<W, D, B, C, E>
where
    W: WalletService,
    D: DatabaseService,
    B: BitcoinRpcService,
    C: CacheService,
    E: EventPublisher,
{
    /// Wallet service for Bitcoin operations
    wallet: Arc<W>,

    /// Database service for persistence
    database: Arc<D>,

    /// Bitcoin RPC service
    bitcoin_rpc: Arc<B>,

    /// Cache service (used in future round state caching)
    #[allow(dead_code)]
    cache: Arc<C>,

    /// Event publisher
    events: Arc<E>,

    /// Service configuration
    config: ArkConfig,

    /// Current round state (cached)
    current_round: RwLock<Option<Round>>,
}

impl<W, D, B, C, E> ArkService<W, D, B, C, E>
where
    W: WalletService,
    D: DatabaseService,
    B: BitcoinRpcService,
    C: CacheService,
    E: EventPublisher,
{
    /// Create a new Ark service
    pub fn new(
        wallet: Arc<W>,
        database: Arc<D>,
        bitcoin_rpc: Arc<B>,
        cache: Arc<C>,
        events: Arc<E>,
        config: ArkConfig,
    ) -> Self {
        Self {
            wallet,
            database,
            bitcoin_rpc,
            cache,
            events,
            config,
            current_round: RwLock::new(None),
        }
    }

    /// Get service configuration
    pub fn config(&self) -> &ArkConfig {
        &self.config
    }

    // =========================================================================
    // Round Operations
    // =========================================================================

    /// Start a new round
    #[instrument(skip(self))]
    pub async fn start_round(&self) -> ArkResult<Round> {
        // Check if there's already an active round
        if let Some(round) = self.get_current_round().await? {
            if !round.status.is_terminal() {
                return Err(ArkError::Internal(
                    "Cannot start new round while another is active".to_string(),
                ));
            }
        }

        // Get current block height
        let current_height = self.bitcoin_rpc.get_block_height().await?;

        // Create round config
        let round_config = RoundConfig {
            min_participants: self.config.min_participants,
            max_participants: self.config.max_participants,
            registration_duration: chrono::Duration::seconds(
                self.config.registration_duration_secs as i64,
            ),
            signing_duration: chrono::Duration::seconds(self.config.signing_duration_secs as i64),
            vtxo_lifetime_blocks: self.config.vtxo_lifetime_blocks,
            current_height,
        };

        // Create the round
        let round = Round::new(round_config);
        info!(round_id = %round.id, "Starting new round");

        // Save to database
        self.database.save_round(&round).await?;

        // Update cached state
        *self.current_round.write().await = Some(round.clone());

        // Publish event
        self.events
            .publish(ArkEvent::RoundStarted { round_id: round.id })
            .await?;

        Ok(round)
    }

    /// Get the current active round
    pub async fn get_current_round(&self) -> ArkResult<Option<Round>> {
        // Check cache first
        let cached = self.current_round.read().await;
        if let Some(ref round) = *cached {
            if !round.status.is_terminal() {
                return Ok(Some(round.clone()));
            }
        }
        drop(cached);

        // Fall back to database
        let round: Option<Round> = self.database.get_active_round().await?;

        // Update cache
        *self.current_round.write().await = round.clone();

        Ok(round)
    }

    /// Get a round by ID
    pub async fn get_round(&self, id: uuid::Uuid) -> ArkResult<Option<Round>> {
        self.database.get_round(id).await
    }

    /// Register a participant for the current round
    #[instrument(skip(self, participant))]
    pub async fn register_participant(&self, participant: Participant) -> ArkResult<()> {
        // Validate participant is not banned
        if self.database.is_banned(&participant.pubkey).await? {
            return Err(ArkError::ParticipantBanned {
                pubkey: participant.pubkey.to_string(),
                until: "unknown".to_string(),
            });
        }

        // Validate VTXO requests
        for request in &participant.vtxo_requests {
            if request.amount.to_sat() < self.config.min_vtxo_amount_sats {
                return Err(ArkError::AmountTooSmall {
                    amount: request.amount.to_sat(),
                    minimum: self.config.min_vtxo_amount_sats,
                });
            }
        }

        // Get current round
        let mut round: Round = self
            .get_current_round()
            .await?
            .ok_or_else(|| ArkError::Internal("No active round".to_string()))?;

        // Add participant
        round
            .add_participant(participant.clone())
            .map_err(|e| ArkError::Internal(format!("Failed to add participant: {}", e)))?;

        // Save updated round
        self.database.save_round(&round).await?;

        // Update cache
        *self.current_round.write().await = Some(round);

        info!(pubkey = %participant.pubkey, "Participant registered");

        Ok(())
    }

    // =========================================================================
    // VTXO Operations
    // =========================================================================

    /// Get a VTXO by ID
    pub async fn get_vtxo(&self, id: &VtxoId) -> ArkResult<Option<Vtxo>> {
        self.database.get_vtxo(id).await
    }

    /// Get all VTXOs owned by a public key
    pub async fn get_vtxos_by_owner(
        &self,
        pubkey: &bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Vec<Vtxo>> {
        self.database.get_vtxos_by_owner(pubkey).await
    }

    /// Get spendable (active) VTXOs for a public key
    pub async fn get_spendable_vtxos(
        &self,
        pubkey: &bitcoin::XOnlyPublicKey,
    ) -> ArkResult<Vec<Vtxo>> {
        let vtxos: Vec<Vtxo> = self.database.get_vtxos_by_owner(pubkey).await?;
        Ok(vtxos
            .into_iter()
            .filter(|v| v.status.is_spendable())
            .collect())
    }

    // =========================================================================
    // Exit Operations
    // =========================================================================

    /// Request a collaborative exit
    #[instrument(skip(self))]
    pub async fn request_collaborative_exit(
        &self,
        requester_pubkey: bitcoin::XOnlyPublicKey,
        vtxo_ids: Vec<VtxoId>,
        destination: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    ) -> ArkResult<Exit> {
        // Validate VTXOs
        let mut total_amount = bitcoin::Amount::ZERO;
        for vtxo_id in &vtxo_ids {
            let vtxo: Vtxo = self
                .database
                .get_vtxo(vtxo_id)
                .await?
                .ok_or_else(|| ArkError::VtxoNotFound(vtxo_id.to_string()))?;

            // Verify ownership
            if vtxo.owner_pubkey != requester_pubkey {
                return Err(ArkError::InvalidExitRequest(
                    "Not the owner of VTXO".to_string(),
                ));
            }

            // Verify spendable
            if !vtxo.status.is_spendable() {
                return Err(ArkError::InvalidExitRequest(format!(
                    "VTXO {} is not spendable (status: {:?})",
                    vtxo_id, vtxo.status
                )));
            }

            total_amount += vtxo.amount;
        }

        // Create exit
        let exit = Exit::collaborative(vtxo_ids, destination, requester_pubkey, total_amount);

        // Save exit
        self.database.save_exit(&exit).await?;

        info!(exit_id = %exit.id, "Collaborative exit requested");

        Ok(exit)
    }

    /// Request a unilateral exit
    #[instrument(skip(self))]
    pub async fn request_unilateral_exit(
        &self,
        requester_pubkey: bitcoin::XOnlyPublicKey,
        vtxo_id: VtxoId,
        destination: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    ) -> ArkResult<Exit> {
        // Get VTXO
        let vtxo: Vtxo = self
            .database
            .get_vtxo(&vtxo_id)
            .await?
            .ok_or_else(|| ArkError::VtxoNotFound(vtxo_id.to_string()))?;

        // Verify ownership
        if vtxo.owner_pubkey != requester_pubkey {
            return Err(ArkError::InvalidExitRequest(
                "Not the owner of VTXO".to_string(),
            ));
        }

        // Verify spendable
        if !vtxo.status.is_spendable() {
            return Err(ArkError::InvalidExitRequest(format!(
                "VTXO is not spendable (status: {:?})",
                vtxo.status
            )));
        }

        // Calculate claimable height (current height + exit delta)
        let current_height = self.bitcoin_rpc.get_block_height().await?;
        let claimable_height = current_height + self.config.exit_delta_blocks;

        // Create exit
        let exit = Exit::unilateral(
            vtxo_id,
            destination,
            requester_pubkey,
            vtxo.amount,
            claimable_height,
        );

        // Save exit
        self.database.save_exit(&exit).await?;

        info!(exit_id = %exit.id, "Unilateral exit requested");

        Ok(exit)
    }

    /// Get an exit by ID
    pub async fn get_exit(&self, id: uuid::Uuid) -> ArkResult<Option<Exit>> {
        self.database.get_exit(id).await
    }

    // =========================================================================
    // Status and Info
    // =========================================================================

    /// Get current block height
    pub async fn get_block_height(&self) -> ArkResult<u32> {
        self.bitcoin_rpc.get_block_height().await
    }

    /// Get ASP wallet balance
    pub async fn get_asp_balance(&self) -> ArkResult<bitcoin::Amount> {
        self.wallet.get_balance().await
    }

    /// Get ASP public key
    pub async fn get_asp_pubkey(&self) -> ArkResult<bitcoin::XOnlyPublicKey> {
        self.wallet.get_asp_pubkey().await
    }
}

/// Service status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServiceStatus {
    /// Current block height
    pub block_height: u32,

    /// ASP wallet balance
    pub asp_balance_sats: u64,

    /// Current round status
    pub current_round: Option<RoundStatusInfo>,

    /// Number of active VTXOs
    pub active_vtxo_count: u64,

    /// Number of pending exits
    pub pending_exit_count: u64,
}

/// Round status for API responses
#[derive(Debug, Clone, serde::Serialize)]
#[allow(missing_docs)]
pub struct RoundStatusInfo {
    pub id: uuid::Uuid,
    pub status: RoundStatus,
    pub participant_count: usize,
    pub registration_deadline: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ArkConfig::default();

        assert!(config.min_participants >= 1);
        assert!(config.max_participants > config.min_participants);
        assert!(config.vtxo_lifetime_blocks > config.exit_delta_blocks);
        assert!(config.min_vtxo_amount_sats >= 546);
    }
}
