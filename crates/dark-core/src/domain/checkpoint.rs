//! Checkpoint transaction — secures offchain transfers between rounds.

use serde::{Deserialize, Serialize};

/// A checkpoint transaction securing offchain transfers between rounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointTx {
    /// Unique identifier
    pub id: String,
    /// The offchain transaction this checkpoint secures
    pub offchain_tx_id: String,
    /// Hex-encoded tapscript locking the checkpoint output
    pub tapscript: String,
    /// Blocks before the checkpoint can be swept
    pub exit_delay: u32,
    /// Unix timestamp of creation
    pub created_at: u64,
    /// Whether this checkpoint has been swept on-chain
    pub swept: bool,
}

impl CheckpointTx {
    /// Create a new checkpoint transaction.
    pub fn new(offchain_tx_id: String, tapscript: String, exit_delay: u32) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            offchain_tx_id,
            tapscript,
            exit_delay,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            swept: false,
        }
    }

    /// Generate a checkpoint tapscript for the given exit delay and pubkey.
    ///
    /// Returns a human-readable script representation:
    /// `OP_CSV(delay) OP_DROP OP_CHECKSIG(pubkey)`
    pub fn checkpoint_tapscript(exit_delay: u32, pubkey_hex: &str) -> String {
        format!("OP_CSV({}) OP_DROP OP_CHECKSIG({})", exit_delay, pubkey_hex)
    }

    /// Mark this checkpoint as swept on-chain.
    pub fn mark_swept(&mut self) {
        self.swept = true;
    }
}

/// Default checkpoint exit delay (~1 day in blocks).
pub const DEFAULT_CHECKPOINT_EXIT_DELAY: u32 = 144;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_new_generates_id() {
        let cp = CheckpointTx::new("tx-1".into(), "script".into(), 144);
        assert!(!cp.id.is_empty());
        assert_eq!(cp.offchain_tx_id, "tx-1");
        assert!(!cp.swept);
    }

    #[test]
    fn test_checkpoint_tapscript_format() {
        let script = CheckpointTx::checkpoint_tapscript(144, "deadbeef");
        assert_eq!(script, "OP_CSV(144) OP_DROP OP_CHECKSIG(deadbeef)");
    }

    #[test]
    fn test_checkpoint_mark_swept() {
        let mut cp = CheckpointTx::new("tx-2".into(), "script".into(), 100);
        assert!(!cp.swept);
        cp.mark_swept();
        assert!(cp.swept);
    }

    #[test]
    fn test_checkpoint_serde_roundtrip() {
        let cp = CheckpointTx::new("tx-3".into(), "tapscript-hex".into(), 288);
        let json = serde_json::to_string(&cp).unwrap();
        let cp2: CheckpointTx = serde_json::from_str(&json).unwrap();
        assert_eq!(cp.id, cp2.id);
        assert_eq!(cp.offchain_tx_id, cp2.offchain_tx_id);
        assert_eq!(cp.tapscript, cp2.tapscript);
        assert_eq!(cp.exit_delay, cp2.exit_delay);
        assert_eq!(cp.swept, cp2.swept);
    }
}
