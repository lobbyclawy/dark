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

    /// Registration phase ended; confirmation phase has started.
    /// Clients should call ConfirmRegistration within the timeout.
    BatchStarted {
        /// Round identifier
        round_id: String,
        /// Intent IDs that were selected for this batch
        intent_ids: Vec<String>,
        /// VTXO tree unsigned PSBT (hex)
        unsigned_vtxo_tree: String,
        /// Unix timestamp when confirmation phase started
        timestamp: i64,
    },

    /// An intent was confirmed by the participant.
    IntentConfirmed {
        /// Round identifier
        round_id: String,
        /// The confirmed intent identifier
        intent_id: String,
        /// Unix timestamp when confirmation was received
        timestamp: i64,
    },

    /// Confirmation phase ended. Unconfirmed intents were dropped.
    ConfirmationPhaseEnded {
        /// Round identifier
        round_id: String,
        /// Number of intents that confirmed
        confirmed_count: u32,
        /// Number of intents that timed out and were dropped
        dropped_count: u32,
        /// Unix timestamp
        timestamp: i64,
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

    // ── Ban/conviction ─────────────────────────────────────────────────
    /// A participant was banned for misbehaviour.
    ParticipantBanned {
        /// Public key of the banned participant
        pubkey: String,
    },

    // ── Server lifecycle ──────────────────────────────────────────────
    /// The Ark server has started.
    ServerStarted {
        /// Server version
        version: String,
        /// Bitcoin network (mainnet, testnet, signet, regtest)
        network: String,
    },

    // ── Fraud detection ────────────────────────────────────────────
    /// Fraud detected: a VTXO was double-spent across rounds.
    FraudDetected {
        /// The double-spent VTXO identifier
        vtxo_id: String,
        /// Round where the fraud was detected
        round_id: String,
    },

    /// The Ark server is shutting down.
    ServerStopping,

    // ── Sweep ─────────────────────────────────────────────────────
    /// A scheduled sweep completed successfully.
    SweepCompleted {
        /// Number of VTXOs swept
        vtxos_swept: usize,
        /// Total satoshis recovered
        sats_recovered: u64,
    },

    // ── MuSig2 tree signing (#159) ────────────────────────────────
    /// All cosigners have submitted their tree nonces.
    TreeNoncesCollected {
        /// Round identifier
        round_id: String,
    },

    /// All cosigners have submitted their partial signatures.
    TreeSignaturesCollected {
        /// Round identifier
        round_id: String,
    },

    /// A tree transaction is ready for cosigning (emitted per VTXO tree node).
    TreeTxReady {
        /// Round identifier
        round_id: String,
        /// Transaction ID of this tree node
        txid: String,
        /// Base64-encoded unsigned PSBT / tx
        tx: String,
        /// Cosigner pubkeys involved in this tree node
        cosigners: Vec<String>,
    },

    /// Tree signing phase has started — cosigners should submit nonces.
    TreeSigningPhaseStarted {
        /// Round identifier
        round_id: String,
        /// Hex-encoded pubkeys of all cosigners
        cosigners_pubkeys: Vec<String>,
        /// Base64-encoded unsigned commitment tx PSBT
        unsigned_commitment_tx: String,
    },

    /// Tree nonces forwarded to cosigners (emitted per tree node).
    TreeNoncesForwarded {
        /// Round identifier
        round_id: String,
        /// Transaction ID of the tree node
        txid: String,
        /// Nonces keyed by cosigner pubkey (pubkey → hex nonce pair)
        nonces_by_pubkey: std::collections::HashMap<String, String>,
    },

    /// The commitment transaction was signed, finalized, and broadcast to the Bitcoin network.
    RoundBroadcast {
        /// Round identifier
        round_id: String,
        /// The on-chain commitment transaction ID
        commitment_txid: String,
        /// Unix timestamp when the broadcast occurred
        timestamp: i64,
    },
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
            Self::BatchStarted { .. } => "round.batch_started",
            Self::IntentConfirmed { .. } => "intent.confirmed",
            Self::ConfirmationPhaseEnded { .. } => "round.confirmation_ended",
            Self::VtxoCreated { .. } => "vtxo.created",
            Self::VtxoSpent { .. } => "vtxo.spent",
            Self::VtxoForfeited { .. } => "vtxo.forfeited",
            Self::TxSubmitted { .. } => "tx.submitted",
            Self::TxFinalized { .. } => "tx.finalized",
            Self::FraudDetected { .. } => "fraud.detected",
            Self::ParticipantBanned { .. } => "participant.banned",
            Self::ServerStarted { .. } => "server.started",
            Self::ServerStopping => "server.stopping",
            Self::SweepCompleted { .. } => "sweep.completed",
            Self::TreeNoncesCollected { .. } => "tree.nonces_collected",
            Self::TreeSignaturesCollected { .. } => "tree.signatures_collected",
            Self::TreeTxReady { .. } => "tree.tx_ready",
            Self::TreeSigningPhaseStarted { .. } => "tree.signing_phase_started",
            Self::TreeNoncesForwarded { .. } => "tree.nonces_forwarded",
            Self::RoundBroadcast { .. } => "round.broadcast",
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
                ArkEvent::BatchStarted {
                    round_id: "r1".into(),
                    intent_ids: vec!["i1".into(), "i2".into()],
                    unsigned_vtxo_tree: "psbt".into(),
                    timestamp: 350,
                },
                "round.batch_started",
            ),
            (
                ArkEvent::IntentConfirmed {
                    round_id: "r1".into(),
                    intent_id: "i1".into(),
                    timestamp: 360,
                },
                "intent.confirmed",
            ),
            (
                ArkEvent::ConfirmationPhaseEnded {
                    round_id: "r1".into(),
                    confirmed_count: 3,
                    dropped_count: 1,
                    timestamp: 370,
                },
                "round.confirmation_ended",
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
                ArkEvent::FraudDetected {
                    vtxo_id: "v1".into(),
                    round_id: "r1".into(),
                },
                "fraud.detected",
            ),
            (
                ArkEvent::ServerStarted {
                    version: "0.1.0".into(),
                    network: "regtest".into(),
                },
                "server.started",
            ),
            (ArkEvent::ServerStopping, "server.stopping"),
            (
                ArkEvent::RoundBroadcast {
                    round_id: "r1".into(),
                    commitment_txid: "txid".into(),
                    timestamp: 500,
                },
                "round.broadcast",
            ),
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
