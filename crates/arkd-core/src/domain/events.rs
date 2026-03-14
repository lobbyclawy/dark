//! Domain events for the Ark protocol (event sourcing).
//!
//! Each significant state change emits an `ArkEvent`, enabling audit trails,
//! replay, metrics, and distributed state synchronization.

use serde::{Deserialize, Serialize};

/// Domain events emitted during Ark protocol operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArkEvent {
    // ── Intent lifecycle ──────────────────────────────────────────────
    /// A new payment intent was registered for inclusion in a round.
    IntentRegistered {
        /// Unique intent identifier
        intent_id: String,
        /// Participant public key
        pubkey: String,
        /// Amount in satoshis
        amount: u64,
    },

    /// An intent expired before being included in a round.
    IntentExpired {
        /// The expired intent identifier
        intent_id: String,
    },

    /// An intent was explicitly deleted by the participant.
    IntentDeleted {
        /// The deleted intent identifier
        intent_id: String,
    },

    // ── Round lifecycle ───────────────────────────────────────────────
    /// A new round has started (registration phase open).
    RoundStarted {
        /// Unique round identifier
        round_id: String,
        /// Unix timestamp when the round started
        timestamp: i64,
    },

    /// A round was successfully finalized with a commitment transaction.
    RoundFinalized {
        /// Round identifier
        round_id: String,
        /// Commitment transaction (hex or PSBT)
        commitment_tx: String,
        /// Unix timestamp when the round ended
        timestamp: i64,
        /// Number of VTXOs created in this round
        vtxo_count: u32,
    },

    /// A round failed to finalize.
    RoundFailed {
        /// Round identifier
        round_id: String,
        /// Human-readable failure reason
        reason: String,
        /// Unix timestamp of the failure
        timestamp: i64,
    },

    // ── VTXO lifecycle ────────────────────────────────────────────────
    /// A new VTXO was created as part of a finalized round.
    VtxoCreated {
        /// VTXO identifier (txid:vout)
        vtxo_id: String,
        /// Owner public key
        pubkey: String,
        /// Amount in satoshis
        amount: u64,
        /// Round that created this VTXO
        round_id: String,
    },

    /// A VTXO was spent in an offchain transaction.
    VtxoSpent {
        /// The spent VTXO identifier
        vtxo_id: String,
        /// Transaction that spent it
        spending_txid: String,
    },

    /// A VTXO was forfeited (connector sweep).
    VtxoForfeited {
        /// The forfeited VTXO identifier
        vtxo_id: String,
        /// Forfeit transaction ID
        forfeit_txid: String,
    },

    // ── Offchain transactions ─────────────────────────────────────────
    /// An offchain transaction was submitted.
    TxSubmitted {
        /// Ark transaction ID
        ark_txid: String,
    },

    /// An offchain transaction was finalized on-chain.
    TxFinalized {
        /// Ark transaction ID
        ark_txid: String,
        /// On-chain commitment transaction ID
        commitment_txid: String,
    },

    // ── Server lifecycle ──────────────────────────────────────────────
    /// The Ark server has started.
    ServerStarted {
        /// Server version
        version: String,
        /// Bitcoin network (mainnet, testnet, signet, regtest)
        network: String,
    },

    /// The Ark server is shutting down.
    ServerStopping,
}

impl ArkEvent {
    /// Human-readable event name for logging and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::IntentRegistered { .. } => "intent.registered",
            Self::IntentExpired { .. } => "intent.expired",
            Self::IntentDeleted { .. } => "intent.deleted",
            Self::RoundStarted { .. } => "round.started",
            Self::RoundFinalized { .. } => "round.finalized",
            Self::RoundFailed { .. } => "round.failed",
            Self::VtxoCreated { .. } => "vtxo.created",
            Self::VtxoSpent { .. } => "vtxo.spent",
            Self::VtxoForfeited { .. } => "vtxo.forfeited",
            Self::TxSubmitted { .. } => "tx.submitted",
            Self::TxFinalized { .. } => "tx.finalized",
            Self::ServerStarted { .. } => "server.started",
            Self::ServerStopping => "server.stopping",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::EventPublisher;
    use crate::ports::LoggingEventPublisher;

    #[test]
    fn test_ark_event_kind_names() {
        let cases: Vec<(ArkEvent, &str)> = vec![
            (
                ArkEvent::IntentRegistered {
                    intent_id: "i1".into(),
                    pubkey: "pk".into(),
                    amount: 1000,
                },
                "intent.registered",
            ),
            (
                ArkEvent::IntentExpired {
                    intent_id: "i1".into(),
                },
                "intent.expired",
            ),
            (
                ArkEvent::IntentDeleted {
                    intent_id: "i1".into(),
                },
                "intent.deleted",
            ),
            (
                ArkEvent::RoundStarted {
                    round_id: "r1".into(),
                    timestamp: 100,
                },
                "round.started",
            ),
            (
                ArkEvent::RoundFinalized {
                    round_id: "r1".into(),
                    commitment_tx: "tx".into(),
                    timestamp: 200,
                    vtxo_count: 5,
                },
                "round.finalized",
            ),
            (
                ArkEvent::RoundFailed {
                    round_id: "r1".into(),
                    reason: "timeout".into(),
                    timestamp: 300,
                },
                "round.failed",
            ),
            (
                ArkEvent::VtxoCreated {
                    vtxo_id: "v1".into(),
                    pubkey: "pk".into(),
                    amount: 500,
                    round_id: "r1".into(),
                },
                "vtxo.created",
            ),
            (
                ArkEvent::VtxoSpent {
                    vtxo_id: "v1".into(),
                    spending_txid: "tx".into(),
                },
                "vtxo.spent",
            ),
            (
                ArkEvent::VtxoForfeited {
                    vtxo_id: "v1".into(),
                    forfeit_txid: "tx".into(),
                },
                "vtxo.forfeited",
            ),
            (
                ArkEvent::TxSubmitted {
                    ark_txid: "atx".into(),
                },
                "tx.submitted",
            ),
            (
                ArkEvent::TxFinalized {
                    ark_txid: "atx".into(),
                    commitment_txid: "ctx".into(),
                },
                "tx.finalized",
            ),
            (
                ArkEvent::ServerStarted {
                    version: "0.1.0".into(),
                    network: "regtest".into(),
                },
                "server.started",
            ),
            (ArkEvent::ServerStopping, "server.stopping"),
        ];

        for (event, expected_kind) in cases {
            assert_eq!(event.kind(), expected_kind, "kind mismatch for {:?}", event);
        }
    }

    #[tokio::test]
    async fn test_logging_publisher_publish() {
        let publisher = LoggingEventPublisher::new(16);
        let result = publisher
            .publish_event(ArkEvent::ServerStarted {
                version: "0.1.0".into(),
                network: "regtest".into(),
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_logging_publisher_subscribe() {
        let publisher = LoggingEventPublisher::new(16);
        let mut rx = publisher.subscribe().await.unwrap();

        let event = ArkEvent::RoundStarted {
            round_id: "r1".into(),
            timestamp: 42,
        };
        publisher.publish_event(event.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.kind(), "round.started");
    }

    #[test]
    fn test_ark_event_serializes_to_json() {
        let event = ArkEvent::RoundFinalized {
            round_id: "r1".into(),
            commitment_tx: "deadbeef".into(),
            timestamp: 1234567890,
            vtxo_count: 3,
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: ArkEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.kind(), "round.finalized");
    }

    #[tokio::test]
    async fn test_event_channel_capacity() {
        let publisher = LoggingEventPublisher::new(4);
        // No subscribers — publishing should not block or error
        for i in 0..10 {
            let result = publisher
                .publish_event(ArkEvent::IntentRegistered {
                    intent_id: format!("i{i}"),
                    pubkey: "pk".into(),
                    amount: 100,
                })
                .await;
            assert!(
                result.is_ok(),
                "publish should not error even without subscribers"
            );
        }
    }
}
