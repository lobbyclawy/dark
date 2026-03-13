//! BIP-322 "Generic Signed Message Format" — Simple signature verification
//!
//! Implements the "Simple" variant of BIP-322 for proving ownership of a
//! Bitcoin address by signing a message. Used by arkd to verify that intent
//! submitters actually own the VTXOs they claim.
//!
//! Reference: <https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki>

use bitcoin::consensus::Encodable;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::opcodes::{all::*, OP_FALSE};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{self, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature as TaprootSignature;
use bitcoin::{
    absolute::LockTime, script::Builder, transaction::Version, Address, Amount, Network, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::error::{BitcoinError, BitcoinResult};

// ── BIP-340 tagged hash tag ──────────────────────────────────────────

/// The tag used for BIP-340 tagged hashing of the message.
const BIP322_TAG: &str = "BIP0322-signed-message";

// ── Public types ─────────────────────────────────────────────────────

/// A BIP-322 "Simple" proof: a message, the address being proved, and the
/// witness-stack signature (consensus-encoded, then typically base64'd).
#[derive(Debug, Clone)]
pub struct Bip322Proof {
    /// The message that was signed (arbitrary bytes).
    pub message: Vec<u8>,
    /// The Bitcoin address whose ownership is being proved.
    pub address: Address,
    /// The serialized witness stack (consensus-encoded `Vec<Vec<u8>>`).
    pub signature: Vec<u8>,
}

impl Bip322Proof {
    /// Verify a BIP-322 simple signature.
    ///
    /// Returns `Ok(true)` if the signature is valid for the given message and
    /// address on `network`, `Ok(false)` if it is structurally sound but
    /// cryptographically invalid, and `Err` on malformed inputs.
    pub fn verify(&self, _network: Network) -> BitcoinResult<bool> {
        // Build `to_spend` and `to_sign` virtual transactions.
        // The address's scriptPubKey fully determines verification — the
        // network parameter is accepted for API symmetry and future use.
        let to_spend = build_to_spend(&self.message, &self.address)?;
        let to_sign = build_to_sign(&to_spend, &self.signature)?;

        // Verify the witness satisfies the script
        verify_simple_witness(&to_spend, &to_sign, &self.address)
    }

    /// Verify that this proof covers a specific message format used for VTXO
    /// ownership in the Ark protocol.
    ///
    /// The expected message is `"arkd intent: {intent_id}"`. The proof must
    /// be valid for the given address, and the address must be derived from
    /// `pubkey` (P2TR with internal key = `pubkey`, no script path).
    pub fn verify_vtxo_ownership(
        &self,
        intent_id: &str,
        pubkey: &XOnlyPublicKey,
        network: Network,
    ) -> BitcoinResult<bool> {
        // Check the message matches the expected format
        let expected_message = format_intent_message(intent_id);
        if self.message != expected_message.as_bytes() {
            return Ok(false);
        }

        // Check the address corresponds to the pubkey (P2TR key-path)
        let secp = Secp256k1::verification_only();
        let expected_address = Address::p2tr(&secp, *pubkey, None, network);
        if self.address != expected_address {
            return Ok(false);
        }

        self.verify(network)
    }
}

// ── Message formatting ───────────────────────────────────────────────

/// Format the message used for intent ownership proofs.
pub fn format_intent_message(intent_id: &str) -> String {
    format!("arkd intent: {intent_id}")
}

// ── BIP-340 tagged hash ──────────────────────────────────────────────

/// Compute `SHA256(SHA256(tag) || SHA256(tag) || msg)` per BIP-340.
fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());

    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

// ── Virtual transactions ─────────────────────────────────────────────

/// Build the BIP-322 `to_spend` virtual transaction.
///
/// ```text
/// nVersion  = 0
/// nLockTime = 0
/// vin[0]:  prevout = 000…000:0xFFFFFFFF, scriptSig = OP_0 PUSH32[message_hash]
/// vout[0]: value = 0, scriptPubKey = <address's scriptPubKey>
/// ```
fn build_to_spend(message: &[u8], address: &Address) -> BitcoinResult<Transaction> {
    let message_hash = tagged_hash(BIP322_TAG, message);

    let mut push_bytes = PushBytesBuf::new();
    push_bytes.extend_from_slice(&message_hash).map_err(|e| {
        BitcoinError::ScriptError(format!("failed to build message_hash push: {e}"))
    })?;

    let script_sig = Builder::new()
        .push_opcode(OP_FALSE)
        .push_slice(push_bytes.as_push_bytes())
        .into_script();

    let prevout = OutPoint {
        txid: Txid::from_byte_array([0u8; 32]),
        vout: 0xFFFFFFFF,
    };

    Ok(Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig,
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: address.script_pubkey(),
        }],
    })
}

/// Build the BIP-322 `to_sign` virtual transaction from a `to_spend` tx and
/// a witness stack (the "simple" signature).
///
/// ```text
/// nVersion  = 0
/// nLockTime = 0
/// vin[0]:  prevout = to_spend.txid():0, scriptWitness = <signature>
/// vout[0]: value = 0, scriptPubKey = OP_RETURN
/// ```
fn build_to_sign(to_spend: &Transaction, witness_bytes: &[u8]) -> BitcoinResult<Transaction> {
    let witness = decode_witness(witness_bytes)?;

    Ok(Transaction {
        version: Version(0),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: to_spend.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ZERO,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
        }],
    })
}

/// Decode a consensus-encoded witness stack.
fn decode_witness(data: &[u8]) -> BitcoinResult<Witness> {
    bitcoin::consensus::deserialize(data)
        .map_err(|e| BitcoinError::SerializationError(format!("invalid witness encoding: {e}")))
}

/// Consensus-encode a witness stack to bytes.
pub fn encode_witness(witness: &Witness) -> BitcoinResult<Vec<u8>> {
    let mut buf = Vec::new();
    witness
        .consensus_encode(&mut buf)
        .map_err(|e| BitcoinError::SerializationError(format!("witness encode error: {e}")))?;
    Ok(buf)
}

// ── Verification ─────────────────────────────────────────────────────

/// Verify the witness of a BIP-322 simple signature for P2TR (Taproot).
///
/// Only supports key-path Taproot spend for now (the dominant case for arkd
/// since VTXO owners are identified by x-only pubkeys).
fn verify_simple_witness(
    to_spend: &Transaction,
    to_sign: &Transaction,
    address: &Address,
) -> BitcoinResult<bool> {
    let script_pubkey = address.script_pubkey();

    // Only P2TR (Taproot key-path) is supported. arkd identifies VTXO owners
    // by x-only pubkeys, so this covers all current use cases.
    // TODO: Add P2WPKH support if legacy VTXO address types are ever needed.
    if !script_pubkey.is_p2tr() {
        return Err(BitcoinError::ScriptError(
            "BIP-322 verification currently only supports P2TR (Taproot) addresses".to_string(),
        ));
    }

    verify_p2tr(to_spend, to_sign, &script_pubkey)
}

/// Verify a P2TR key-path BIP-322 signature.
fn verify_p2tr(
    to_spend: &Transaction,
    to_sign: &Transaction,
    script_pubkey: &ScriptBuf,
) -> BitcoinResult<bool> {
    let secp = Secp256k1::verification_only();

    // Extract x-only pubkey from P2TR scriptPubKey.
    // Layout: OP_1 (0x51) | OP_PUSHBYTES_32 (0x20) | <32-byte x-only key>
    // So the key occupies bytes [2..34].
    let pk_bytes = &script_pubkey.as_bytes()[2..34];
    let x_only = XOnlyPublicKey::from_slice(pk_bytes)
        .map_err(|e| BitcoinError::ScriptError(format!("invalid P2TR pubkey: {e}")))?;

    // The witness must have exactly 1 element (64 or 65 byte Schnorr signature)
    let witness = &to_sign.input[0].witness;
    if witness.len() != 1 {
        return Ok(false);
    }

    let sig_bytes = witness
        .nth(0)
        .ok_or_else(|| BitcoinError::ScriptError("missing witness element".to_string()))?;

    let taproot_sig = match TaprootSignature::from_slice(sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(false),
    };

    // Compute the sighash for vin[0] of to_sign
    let prevouts = [TxOut {
        value: Amount::ZERO,
        script_pubkey: to_spend.output[0].script_pubkey.clone(),
    }];

    let mut sighash_cache = SighashCache::new(to_sign);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), taproot_sig.sighash_type)
        .map_err(|e| BitcoinError::ScriptError(format!("sighash computation failed: {e}")))?;

    let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
    match secp.verify_schnorr(&taproot_sig.signature, &msg, &x_only) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::key::{Keypair, TapTweak};
    use bitcoin::sighash::TapSighashType;
    use bitcoin::taproot::Signature as TaprootSignature;

    /// Helper: create a valid BIP-322 proof for a given message and keypair.
    fn create_test_proof(message: &[u8], keypair: &Keypair, network: Network) -> Bip322Proof {
        let secp = Secp256k1::new();
        let (x_only, _parity) = keypair.x_only_public_key();
        let address = Address::p2tr(&secp, x_only, None, network);

        // Taproot key-path spend requires signing with the tweaked keypair
        let tweaked = keypair.tap_tweak(&secp, None);
        let signing_keypair = tweaked.to_inner();

        let to_spend = build_to_spend(message, &address).unwrap();

        // Build unsigned to_sign
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

        // Compute sighash
        let prevouts = [TxOut {
            value: Amount::ZERO,
            script_pubkey: to_spend.output[0].script_pubkey.clone(),
        }];

        let mut sighash_cache = SighashCache::new(&to_sign_unsigned);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();

        let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
        let schnorr_sig = secp.sign_schnorr(&msg, &signing_keypair);

        let taproot_sig = TaprootSignature {
            signature: schnorr_sig,
            sighash_type: TapSighashType::Default,
        };

        // Build witness with the signature
        let mut witness = Witness::new();
        witness.push(taproot_sig.serialize());

        let witness_bytes = encode_witness(&witness).unwrap();

        Bip322Proof {
            message: message.to_vec(),
            address,
            signature: witness_bytes,
        }
    }

    fn test_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let secret_bytes = [0x01u8; 32]; // deterministic test key
        Keypair::from_seckey_slice(&secp, &secret_bytes).unwrap()
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let h1 = tagged_hash(BIP322_TAG, b"hello");
        let h2 = tagged_hash(BIP322_TAG, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tagged_hash_different_messages() {
        let h1 = tagged_hash(BIP322_TAG, b"hello");
        let h2 = tagged_hash(BIP322_TAG, b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_build_to_spend_structure() {
        let secp = Secp256k1::new();
        let kp = test_keypair();
        let (x_only, _) = kp.x_only_public_key();
        let address = Address::p2tr(&secp, x_only, None, Network::Regtest);

        let tx = build_to_spend(b"test message", &address).unwrap();

        assert_eq!(tx.version, Version(0));
        assert_eq!(tx.lock_time, LockTime::ZERO);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value, Amount::ZERO);
        assert_eq!(tx.output[0].script_pubkey, address.script_pubkey());

        // vin[0] prevout must be 000...000:0xFFFFFFFF
        assert_eq!(
            tx.input[0].previous_output.txid,
            Txid::from_byte_array([0u8; 32])
        );
        assert_eq!(tx.input[0].previous_output.vout, 0xFFFFFFFF);
    }

    #[test]
    fn test_verify_valid_proof() {
        let kp = test_keypair();
        let proof = create_test_proof(b"hello world", &kp, Network::Regtest);
        assert!(proof.verify(Network::Regtest).unwrap());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let kp = test_keypair();
        let mut proof = create_test_proof(b"hello world", &kp, Network::Regtest);
        // Tamper with the message
        proof.message = b"tampered message".to_vec();
        assert!(!proof.verify(Network::Regtest).unwrap());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let secp = Secp256k1::new();
        let kp = test_keypair();
        let mut proof = create_test_proof(b"hello world", &kp, Network::Regtest);

        // Replace address with a different key's address
        let other_kp = Keypair::from_seckey_slice(&secp, &[0x02u8; 32]).unwrap();
        let (other_x, _) = other_kp.x_only_public_key();
        proof.address = Address::p2tr(&secp, other_x, None, Network::Regtest);

        assert!(!proof.verify(Network::Regtest).unwrap());
    }

    #[test]
    fn test_verify_tampered_signature_fails() {
        let kp = test_keypair();
        let mut proof = create_test_proof(b"hello world", &kp, Network::Regtest);

        // Tamper with a byte in the signature
        if let Some(byte) = proof.signature.get_mut(5) {
            *byte ^= 0xFF;
        }
        // Should either return false or error (both are acceptable)
        match proof.verify(Network::Regtest) {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // deserialization error is also fine
        }
    }

    #[test]
    fn test_verify_different_network_still_verifies_crypto() {
        let kp = test_keypair();
        let proof = create_test_proof(b"hello world", &kp, Network::Regtest);
        // Crypto verification is network-agnostic (same scriptPubKey)
        // so passing a different network still returns true.
        assert!(proof.verify(Network::Bitcoin).unwrap());
    }

    #[test]
    fn test_verify_vtxo_ownership_valid() {
        let kp = test_keypair();
        let (x_only, _) = kp.x_only_public_key();
        let intent_id = "test-intent-123";
        let message = format_intent_message(intent_id);

        let proof = create_test_proof(message.as_bytes(), &kp, Network::Regtest);
        assert!(proof
            .verify_vtxo_ownership(intent_id, &x_only, Network::Regtest)
            .unwrap());
    }

    #[test]
    fn test_verify_vtxo_ownership_wrong_intent_id() {
        let kp = test_keypair();
        let (x_only, _) = kp.x_only_public_key();
        let message = format_intent_message("intent-A");

        let proof = create_test_proof(message.as_bytes(), &kp, Network::Regtest);
        // Verify with different intent ID
        assert!(!proof
            .verify_vtxo_ownership("intent-B", &x_only, Network::Regtest)
            .unwrap());
    }

    #[test]
    fn test_verify_vtxo_ownership_wrong_pubkey() {
        let secp = Secp256k1::new();
        let kp = test_keypair();
        let intent_id = "test-intent";
        let message = format_intent_message(intent_id);

        let proof = create_test_proof(message.as_bytes(), &kp, Network::Regtest);

        // Use a different pubkey for verification
        let other_kp = Keypair::from_seckey_slice(&secp, &[0x02u8; 32]).unwrap();
        let (other_x, _) = other_kp.x_only_public_key();
        assert!(!proof
            .verify_vtxo_ownership(intent_id, &other_x, Network::Regtest)
            .unwrap());
    }

    #[test]
    fn test_format_intent_message() {
        assert_eq!(format_intent_message("abc-123"), "arkd intent: abc-123");
    }

    #[test]
    fn test_encode_decode_witness_roundtrip() {
        let mut witness = Witness::new();
        witness.push([0x01, 0x02, 0x03]);
        witness.push([0x04, 0x05]);

        let encoded = encode_witness(&witness).unwrap();
        let decoded = decode_witness(&encoded).unwrap();
        assert_eq!(witness, decoded);
    }

    #[test]
    fn test_decode_invalid_witness() {
        assert!(decode_witness(&[0xFF, 0xFF, 0xFF]).is_err());
    }

    #[test]
    fn test_verify_multiple_messages_same_key() {
        let kp = test_keypair();
        for msg in &[b"msg1".as_slice(), b"msg2", b"msg3"] {
            let proof = create_test_proof(msg, &kp, Network::Regtest);
            assert!(proof.verify(Network::Regtest).unwrap());
        }
    }

    #[test]
    fn test_verify_empty_message() {
        let kp = test_keypair();
        let proof = create_test_proof(b"", &kp, Network::Regtest);
        assert!(proof.verify(Network::Regtest).unwrap());
    }
}
