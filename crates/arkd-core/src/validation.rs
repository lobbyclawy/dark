//! Input validation for the Ark protocol
//!
//! Centralised validation functions that reject malformed or out-of-range
//! inputs **before** they reach domain logic. Every public entry-point in
//! `ArkService` should call the appropriate validator.

use crate::error::{ArkError, ArkResult};

// ── Constants ────────────────────────────────────────────────────────

/// Absolute maximum number of VTXOs in a single request / round.
/// Prevents OOM from pathologically large batches.
pub const MAX_VTXO_COUNT: usize = 4096;

/// Maximum tree depth for VTXO Taproot trees.
/// A depth of 32 already supports 2^32 leaves — far beyond practical need.
pub const MAX_TREE_DEPTH: u32 = 32;

/// Minimum fee rate in sat/vB (below this, transactions won't propagate).
pub const MIN_FEE_RATE_SAT_VB: u64 = 1;

/// Maximum fee rate in sat/vB (sanity cap to avoid fee-sniping bugs).
pub const MAX_FEE_RATE_SAT_VB: u64 = 100_000;

/// Maximum amount in satoshis (21 million BTC).
pub const MAX_AMOUNT_SATS: u64 = 2_100_000_000_000_000;

/// Minimum timelock value in blocks (must be positive).
pub const MIN_TIMELOCK_BLOCKS: u32 = 1;

/// Maximum timelock in blocks (~10 years at 144 blocks/day).
pub const MAX_TIMELOCK_BLOCKS: u32 = 525_960;

/// Minimum timelock value in seconds (must be > LOCKTIME_THRESHOLD).
pub const MIN_TIMELOCK_SECONDS: u32 = 500_000_001;

/// Maximum timelock in seconds (~10 years from now is generous).
pub const MAX_TIMELOCK_SECONDS: u32 = 1_893_456_000; // ~2030-01-01

// ── Validators ───────────────────────────────────────────────────────

/// Validate a satoshi amount is within sane bounds.
pub fn validate_amount(amount: u64, context: &str) -> ArkResult<()> {
    if amount == 0 {
        return Err(ArkError::AmountTooSmall {
            amount: 0,
            minimum: 1,
        });
    }
    if amount > MAX_AMOUNT_SATS {
        return Err(ArkError::InvalidConfiguration(format!(
            "{context}: amount {amount} exceeds maximum {MAX_AMOUNT_SATS} sats"
        )));
    }
    Ok(())
}

/// Validate a hex-encoded public key (32-byte x-only or 33-byte compressed).
pub fn validate_pubkey_hex(hex_str: &str, context: &str) -> ArkResult<()> {
    if hex_str.is_empty() {
        return Err(ArkError::InvalidPublicKey(format!(
            "{context}: empty public key"
        )));
    }

    let bytes = hex::decode(hex_str)
        .map_err(|e| ArkError::InvalidPublicKey(format!("{context}: invalid hex encoding: {e}")))?;

    match bytes.len() {
        32 => {
            // x-only / Schnorr key
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&bytes).map_err(|e| {
                ArkError::InvalidPublicKey(format!("{context}: invalid x-only pubkey: {e}"))
            })?;
        }
        33 => {
            // Compressed SEC1 key
            bitcoin::secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                ArkError::InvalidPublicKey(format!("{context}: invalid compressed pubkey: {e}"))
            })?;
        }
        other => {
            return Err(ArkError::InvalidPublicKey(format!(
                "{context}: expected 32 or 33 bytes, got {other}"
            )));
        }
    }

    Ok(())
}

/// Validate a transaction ID (64-char lowercase hex).
pub fn validate_txid(txid: &str, context: &str) -> ArkResult<()> {
    if txid.is_empty() {
        return Err(ArkError::Internal(format!("{context}: empty txid")));
    }
    if txid.len() != 64 {
        return Err(ArkError::Internal(format!(
            "{context}: txid must be 64 hex chars, got {}",
            txid.len()
        )));
    }
    if !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ArkError::Internal(format!(
            "{context}: txid contains non-hex characters"
        )));
    }
    Ok(())
}

/// Validate VTXO count is within bounds.
pub fn validate_vtxo_count(count: usize, context: &str) -> ArkResult<()> {
    if count == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: VTXO count must be > 0"
        )));
    }
    if count > MAX_VTXO_COUNT {
        return Err(ArkError::Internal(format!(
            "{context}: VTXO count {count} exceeds maximum {MAX_VTXO_COUNT}"
        )));
    }
    Ok(())
}

/// Validate tree depth is within safe bounds.
pub fn validate_tree_depth(depth: u32, context: &str) -> ArkResult<()> {
    if depth == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: tree depth must be > 0"
        )));
    }
    if depth > MAX_TREE_DEPTH {
        return Err(ArkError::Internal(format!(
            "{context}: tree depth {depth} exceeds maximum {MAX_TREE_DEPTH}"
        )));
    }
    Ok(())
}

/// Validate a fee rate in sat/vB.
pub fn validate_fee_rate(sat_per_vb: u64, context: &str) -> ArkResult<()> {
    if sat_per_vb < MIN_FEE_RATE_SAT_VB {
        return Err(ArkError::Internal(format!(
            "{context}: fee rate {sat_per_vb} sat/vB below minimum {MIN_FEE_RATE_SAT_VB}"
        )));
    }
    if sat_per_vb > MAX_FEE_RATE_SAT_VB {
        return Err(ArkError::Internal(format!(
            "{context}: fee rate {sat_per_vb} sat/vB exceeds maximum {MAX_FEE_RATE_SAT_VB}"
        )));
    }
    Ok(())
}

/// Validate a block-height timelock value.
pub fn validate_timelock_blocks(blocks: u32, context: &str) -> ArkResult<()> {
    if blocks < MIN_TIMELOCK_BLOCKS {
        return Err(ArkError::Internal(format!(
            "{context}: timelock {blocks} blocks is below minimum {MIN_TIMELOCK_BLOCKS}"
        )));
    }
    if blocks > MAX_TIMELOCK_BLOCKS {
        return Err(ArkError::Internal(format!(
            "{context}: timelock {blocks} blocks exceeds maximum {MAX_TIMELOCK_BLOCKS}"
        )));
    }
    Ok(())
}

/// Validate an exit delay (the CSV relative timelock for unilateral exits).
pub fn validate_exit_delay(blocks: u32, context: &str) -> ArkResult<()> {
    // Exit delay uses CSV, which is a 16-bit field (max 65535).
    if blocks == 0 {
        return Err(ArkError::Internal(format!(
            "{context}: exit delay must be > 0"
        )));
    }
    if blocks > 65535 {
        return Err(ArkError::Internal(format!(
            "{context}: exit delay {blocks} exceeds CSV maximum 65535"
        )));
    }
    Ok(())
}

// ── Intent proof validation ──────────────────────────────────────────

/// Validate a BIP-322 intent proof.
///
/// Checks that:
/// 1. The proof message matches the expected format for this intent
/// 2. The proof signature is valid for the claimed address and network
pub fn validate_intent_proof(
    proof: &arkd_bitcoin::bip322::Bip322Proof,
    intent_id: &str,
    network: bitcoin::Network,
) -> ArkResult<()> {
    if intent_id.is_empty() {
        return Err(ArkError::InvalidVtxoProof(
            "intent_id must not be empty".to_string(),
        ));
    }

    // Check the message matches the expected format
    let expected_message = arkd_bitcoin::bip322::format_intent_message(intent_id);
    if proof.message != expected_message.as_bytes() {
        return Err(ArkError::InvalidVtxoProof(format!(
            "proof message does not match expected format for intent {intent_id}"
        )));
    }

    // Verify the BIP-322 signature
    match proof.verify(network) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ArkError::InvalidSignature(format!(
            "BIP-322 signature verification failed for intent {intent_id}"
        ))),
        Err(e) => Err(ArkError::InvalidVtxoProof(format!(
            "BIP-322 proof verification error: {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_amount_zero() {
        assert!(validate_amount(0, "test").is_err());
    }

    #[test]
    fn test_validate_amount_too_large() {
        assert!(validate_amount(MAX_AMOUNT_SATS + 1, "test").is_err());
    }

    #[test]
    fn test_validate_amount_valid() {
        assert!(validate_amount(546, "test").is_ok());
        assert!(validate_amount(MAX_AMOUNT_SATS, "test").is_ok());
    }

    #[test]
    fn test_validate_pubkey_hex_empty() {
        assert!(validate_pubkey_hex("", "test").is_err());
    }

    #[test]
    fn test_validate_pubkey_hex_invalid() {
        assert!(validate_pubkey_hex("not_hex", "test").is_err());
        assert!(validate_pubkey_hex("deadbeef", "test").is_err()); // wrong length
    }

    #[test]
    fn test_validate_pubkey_hex_valid_xonly() {
        // Valid x-only key (32 bytes)
        let pk = "0202020202020202020202020202020202020202020202020202020202020202";
        assert!(validate_pubkey_hex(pk, "test").is_ok());
    }

    #[test]
    fn test_validate_txid_valid() {
        let txid = "a".repeat(64);
        assert!(validate_txid(&txid, "test").is_ok());
    }

    #[test]
    fn test_validate_txid_invalid() {
        assert!(validate_txid("", "test").is_err());
        assert!(validate_txid("short", "test").is_err());
        assert!(validate_txid(&"g".repeat(64), "test").is_err()); // non-hex
    }

    #[test]
    fn test_validate_vtxo_count() {
        assert!(validate_vtxo_count(0, "test").is_err());
        assert!(validate_vtxo_count(MAX_VTXO_COUNT + 1, "test").is_err());
        assert!(validate_vtxo_count(1, "test").is_ok());
        assert!(validate_vtxo_count(MAX_VTXO_COUNT, "test").is_ok());
    }

    #[test]
    fn test_validate_tree_depth() {
        assert!(validate_tree_depth(0, "test").is_err());
        assert!(validate_tree_depth(MAX_TREE_DEPTH + 1, "test").is_err());
        assert!(validate_tree_depth(1, "test").is_ok());
        assert!(validate_tree_depth(MAX_TREE_DEPTH, "test").is_ok());
    }

    #[test]
    fn test_validate_fee_rate() {
        assert!(validate_fee_rate(0, "test").is_err());
        assert!(validate_fee_rate(MAX_FEE_RATE_SAT_VB + 1, "test").is_err());
        assert!(validate_fee_rate(1, "test").is_ok());
        assert!(validate_fee_rate(MAX_FEE_RATE_SAT_VB, "test").is_ok());
    }

    #[test]
    fn test_validate_timelock_blocks() {
        assert!(validate_timelock_blocks(0, "test").is_err());
        assert!(validate_timelock_blocks(MAX_TIMELOCK_BLOCKS + 1, "test").is_err());
        assert!(validate_timelock_blocks(1, "test").is_ok());
        assert!(validate_timelock_blocks(144, "test").is_ok());
    }

    #[test]
    fn test_validate_exit_delay() {
        assert!(validate_exit_delay(0, "test").is_err());
        assert!(validate_exit_delay(65536, "test").is_err());
        assert!(validate_exit_delay(1, "test").is_ok());
        assert!(validate_exit_delay(512, "test").is_ok());
        assert!(validate_exit_delay(65535, "test").is_ok());
    }

    // ── Intent proof validation tests ────────────────────────────────

    mod intent_proof_tests {
        use super::*;
        use arkd_bitcoin::bip322::{self, Bip322Proof};
        use bitcoin::key::{Keypair, TapTweak};
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::Network;

        /// Helper to create a valid BIP-322 proof for testing.
        fn make_valid_proof(intent_id: &str) -> Bip322Proof {
            use bitcoin::hashes::{sha256, Hash, HashEngine};
            use bitcoin::opcodes::all::OP_RETURN;
            use bitcoin::opcodes::OP_FALSE;
            use bitcoin::script::PushBytesBuf;
            use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
            use bitcoin::taproot::Signature as TaprootSignature;
            use bitcoin::{
                absolute::LockTime, script::Builder, transaction::Version, Amount, OutPoint,
                ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
            };

            let secp = Secp256k1::new();
            let keypair = Keypair::from_seckey_slice(&secp, &[0x01u8; 32]).unwrap();
            let (x_only, _) = keypair.x_only_public_key();
            let address = bitcoin::Address::p2tr(&secp, x_only, None, Network::Regtest);
            let message = bip322::format_intent_message(intent_id);

            // Taproot key-path spend requires the tweaked keypair
            let tweaked = keypair.tap_tweak(&secp, None);
            let signing_keypair = tweaked.to_keypair();

            // Build to_spend
            let msg_hash = {
                let tag_hash = sha256::Hash::hash(b"BIP0322-signed-message");
                let mut engine = sha256::Hash::engine();
                engine.input(tag_hash.as_ref());
                engine.input(tag_hash.as_ref());
                engine.input(message.as_bytes());
                sha256::Hash::from_engine(engine).to_byte_array()
            };

            let mut push_bytes = PushBytesBuf::new();
            push_bytes.extend_from_slice(&msg_hash).unwrap();
            let script_sig = Builder::new()
                .push_opcode(OP_FALSE)
                .push_slice(push_bytes.as_push_bytes())
                .into_script();

            let to_spend = Transaction {
                version: Version(0),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0u8; 32]),
                        vout: 0xFFFFFFFF,
                    },
                    script_sig,
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: address.script_pubkey(),
                }],
            };

            // Build and sign to_sign
            let to_sign_unsigned = Transaction {
                version: Version(0),
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: to_spend.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ZERO,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::ZERO,
                    script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
                }],
            };

            let prevouts = [TxOut {
                value: Amount::ZERO,
                script_pubkey: to_spend.output[0].script_pubkey.clone(),
            }];

            let mut cache = SighashCache::new(&to_sign_unsigned);
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();

            let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_schnorr(&msg, &signing_keypair);
            let taproot_sig = TaprootSignature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            };

            let mut witness = Witness::new();
            witness.push(taproot_sig.serialize());

            let witness_bytes = bip322::encode_witness(&witness).unwrap();

            Bip322Proof {
                message: message.into_bytes(),
                address,
                signature: witness_bytes,
            }
        }

        #[test]
        fn test_validate_intent_proof_valid() {
            let proof = make_valid_proof("test-intent-1");
            assert!(validate_intent_proof(&proof, "test-intent-1", Network::Regtest).is_ok());
        }

        #[test]
        fn test_validate_intent_proof_empty_id() {
            let proof = make_valid_proof("test-intent-1");
            let result = validate_intent_proof(&proof, "", Network::Regtest);
            assert!(result.is_err());
        }

        #[test]
        fn test_validate_intent_proof_wrong_id() {
            let proof = make_valid_proof("test-intent-1");
            let result = validate_intent_proof(&proof, "wrong-intent", Network::Regtest);
            assert!(result.is_err());
        }
    }
}
