//! Forfeit record persistence model.

use serde::{Deserialize, Serialize};

/// A recorded forfeit transaction submitted by a user during a round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitRecord {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Round this forfeit belongs to.
    pub round_id: String,
    /// VTXO being forfeited.
    pub vtxo_id: String,
    /// Hex-encoded forfeit transaction.
    pub tx_hex: String,
    /// Unix timestamp when the record was submitted.
    pub submitted_at: u64,
    /// Whether the ASP has validated the forfeit signature.
    pub validated: bool,
}

impl ForfeitRecord {
    /// Create a new unvalidated forfeit record with a random ID and current timestamp.
    pub fn new(round_id: String, vtxo_id: String, tx_hex: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            round_id,
            vtxo_id,
            tx_hex,
            submitted_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            validated: false,
        }
    }

    /// Mark this forfeit record as validated by the ASP.
    pub fn mark_validated(&mut self) {
        self.validated = true;
    }
}
