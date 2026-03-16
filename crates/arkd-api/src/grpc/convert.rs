//! Conversion helpers between domain types and protobuf types.

use crate::proto::ark_v1;
use arkd_core::domain::{Round, RoundStage, Vtxo, VtxoOutpoint};

/// Convert a domain `Vtxo` to the protobuf `Vtxo`.
pub fn vtxo_to_proto(vtxo: &Vtxo) -> ark_v1::Vtxo {
    ark_v1::Vtxo {
        outpoint: Some(ark_v1::Outpoint {
            txid: vtxo.outpoint.txid.clone(),
            vout: vtxo.outpoint.vout,
        }),
        amount: vtxo.amount,
        script: vtxo.pubkey.clone(),
        created_at: vtxo.created_at,
        expires_at: vtxo.expires_at,
        commitment_txids: vtxo.commitment_txids.clone(),
        is_preconfirmed: vtxo.preconfirmed,
        is_swept: vtxo.swept,
        is_unrolled: vtxo.unrolled,
        is_spent: vtxo.spent,
        spent_by: vtxo.spent_by.clone(),
        settled_by: vtxo.settled_by.clone(),
        ark_txid: vtxo.ark_txid.clone(),
    }
}

/// Convert a domain `Round` to the protobuf `Round`.
pub fn round_to_proto(round: &Round) -> ark_v1::Round {
    ark_v1::Round {
        id: round.id.clone(),
        starting_timestamp: round.starting_timestamp,
        ending_timestamp: round.ending_timestamp,
        stage: match round.stage.code {
            RoundStage::Undefined => "UNDEFINED".to_string(),
            RoundStage::Registration => "REGISTRATION".to_string(),
            RoundStage::Finalization => "FINALIZATION".to_string(),
        },
        commitment_txid: round.commitment_txid.clone(),
        failed: round.stage.failed,
    }
}

/// Convert a domain `Round` to the protobuf `RoundDetails`.
pub fn round_to_details_proto(round: &Round) -> ark_v1::RoundDetails {
    ark_v1::RoundDetails {
        id: round.id.clone(),
        starting_timestamp: round.starting_timestamp,
        ending_timestamp: round.ending_timestamp,
        stage: match round.stage.code {
            RoundStage::Undefined => "UNDEFINED".to_string(),
            RoundStage::Registration => "REGISTRATION".to_string(),
            RoundStage::Finalization => "FINALIZATION".to_string(),
        },
        commitment_txid: round.commitment_txid.clone(),
        failed: round.stage.failed,
        intent_count: round.intents.len() as u32,
    }
}

/// Parse a protobuf `Outpoint` into a domain `VtxoOutpoint`.
pub fn proto_outpoint_to_domain(outpoint: &ark_v1::Outpoint) -> VtxoOutpoint {
    VtxoOutpoint {
        txid: outpoint.txid.clone(),
        vout: outpoint.vout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkd_core::domain::VtxoOutpoint;

    #[test]
    fn test_vtxo_to_proto_roundtrip() {
        let vtxo = Vtxo::new(
            VtxoOutpoint::new("abc123".to_string(), 0),
            50_000,
            "pubkey123".to_string(),
        );
        let proto = vtxo_to_proto(&vtxo);
        assert_eq!(proto.amount, 50_000);
        assert_eq!(proto.script, "pubkey123");
        let op = proto.outpoint.unwrap();
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 0);
    }

    #[test]
    fn test_round_to_proto() {
        let round = Round::new();
        let proto = round_to_proto(&round);
        assert!(!proto.id.is_empty());
        assert_eq!(proto.stage, "UNDEFINED");
        assert!(!proto.failed);
    }

    #[test]
    fn test_proto_outpoint_to_domain() {
        let proto = ark_v1::Outpoint {
            txid: "deadbeef".to_string(),
            vout: 1,
        };
        let domain = proto_outpoint_to_domain(&proto);
        assert_eq!(domain.txid, "deadbeef");
        assert_eq!(domain.vout, 1);
    }
}
