//! Forfeit transaction construction and verification
//!
//! Forfeit transactions are the core security mechanism of Ark. When a participant
//! is selected for a round, they sign a forfeit transaction that lets the ASP claim
//! the participant's VTXO if the participant tries to double-spend.
//!
//! A forfeit tx has two inputs:
//! - Input 0: the VTXO being forfeited
//! - Input 1: a connector output binding this forfeit to a specific round
//!
//! And one output:
//! - Output 0: pays the combined value (minus fees) to the ASP's pubkey

use bitcoin::hashes::Hash;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{self, schnorr::Signature, Message, Secp256k1};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::TapSighashType;
use bitcoin::{
    absolute, transaction, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey,
};
use thiserror::Error;

/// Errors specific to forfeit transaction operations
#[derive(Error, Debug)]
pub enum ForfeitError {
    /// Fee exceeds the available input amount
    #[error("Fee {fee_sats} sats exceeds available amount {available_sats} sats")]
    FeeExceedsAmount { fee_sats: u64, available_sats: u64 },

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Sighash computation failed
    #[error("Sighash error: {0}")]
    SighashError(String),

    /// PSBT error
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

/// An unsigned forfeit transaction: spends a VTXO + a connector output → pays to ASP
#[derive(Debug, Clone)]
pub struct ForfeitTx {
    /// The VTXO being forfeited (input 0)
    pub vtxo_input: OutPoint,
    /// The connector output binding this forfeit to a round (input 1)
    pub connector_input: OutPoint,
    /// Amount going to ASP (vtxo_amount + connector_amount - fees)
    pub asp_output_amount: Amount,
    /// ASP's tweaked public key (recipient of forfeited funds)
    pub asp_pubkey: TweakedPublicKey,
    /// The unsigned transaction
    pub tx: Transaction,
}

/// Estimated virtual size of a forfeit transaction in vbytes.
/// 2 taproot key-path inputs (~58 vB each) + 1 taproot output (~43 vB) + overhead (~10 vB).
const ESTIMATED_FORFEIT_VSIZE: u64 = 170;

impl ForfeitTx {
    /// Build an unsigned forfeit transaction.
    ///
    /// The transaction spends the VTXO outpoint and a connector outpoint,
    /// paying the combined value (minus estimated fees) to the ASP's taproot key.
    pub fn build(
        vtxo_outpoint: OutPoint,
        vtxo_amount: Amount,
        connector_outpoint: OutPoint,
        connector_amount: Amount,
        asp_pubkey: TweakedPublicKey,
        fee_rate_sats_per_vb: u64,
    ) -> Result<Self, ForfeitError> {
        let total_in = vtxo_amount
            .to_sat()
            .checked_add(connector_amount.to_sat())
            .ok_or_else(|| ForfeitError::TransactionError("Input overflow".to_string()))?;

        let fee = fee_rate_sats_per_vb.saturating_mul(ESTIMATED_FORFEIT_VSIZE);
        if fee >= total_in {
            return Err(ForfeitError::FeeExceedsAmount {
                fee_sats: fee,
                available_sats: total_in,
            });
        }

        let asp_output_amount = Amount::from_sat(total_in - fee);

        // Taproot output script: OP_1 <tweaked_asp_pubkey>
        let asp_script = ScriptBuf::new_p2tr_tweaked(asp_pubkey);

        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: vtxo_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                },
                TxIn {
                    previous_output: connector_outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                },
            ],
            output: vec![TxOut {
                value: asp_output_amount,
                script_pubkey: asp_script,
            }],
        };

        Ok(Self {
            vtxo_input: vtxo_outpoint,
            connector_input: connector_outpoint,
            asp_output_amount,
            asp_pubkey,
            tx,
        })
    }

    /// Verify a Schnorr signature over input 0 (the VTXO input) of this forfeit transaction.
    ///
    /// `vtxo_script` and `vtxo_amount` are needed to compute the correct sighash
    /// for the taproot key-path spend.
    pub fn verify_vtxo_signature(
        &self,
        sig: &Signature,
        vtxo_pubkey: &XOnlyPublicKey,
        vtxo_amount: Amount,
        connector_amount: Amount,
    ) -> Result<bool, ForfeitError> {
        let vtxo_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(*vtxo_pubkey),
        );
        let connector_script = ScriptBuf::new_p2tr_tweaked(self.asp_pubkey);

        let prevouts = vec![
            TxOut {
                value: vtxo_amount,
                script_pubkey: vtxo_script,
            },
            TxOut {
                value: connector_amount,
                script_pubkey: connector_script,
            },
        ];

        let mut cache = SighashCache::new(&self.tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| ForfeitError::SighashError(e.to_string()))?;

        let msg = Message::from_digest(sighash.to_byte_array());
        let secp = Secp256k1::verification_only();

        match secp.verify_schnorr(sig, &msg, vtxo_pubkey) {
            Ok(()) => Ok(true),
            Err(secp256k1::Error::IncorrectSignature) => Ok(false),
            Err(e) => Err(ForfeitError::InvalidSignature(e.to_string())),
        }
    }

    /// Transaction ID of the forfeit transaction
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }
}

/// A forfeit transaction with the VTXO owner's signature attached
#[derive(Debug, Clone)]
pub struct SignedForfeitTx {
    /// The underlying forfeit transaction
    pub forfeit_tx: ForfeitTx,
    /// Schnorr signature from the VTXO owner over input 0
    pub vtxo_signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoin::Txid;

    fn test_keypair() -> (Keypair, XOnlyPublicKey, TweakedPublicKey) {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut secp256k1::rand::thread_rng());
        let (xonly, _parity) = kp.x_only_public_key();
        let (tweaked, _parity) = xonly.tap_tweak(&secp, None);
        (kp, xonly, tweaked)
    }

    fn dummy_outpoint(index: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([index as u8; 32]),
            vout: 0,
        }
    }

    #[test]
    fn test_build_forfeit_tx_correct_inputs() {
        let (_kp, _asp_pk, asp_tweaked) = test_keypair();
        let vtxo_out = dummy_outpoint(1);
        let conn_out = dummy_outpoint(2);

        let forfeit = ForfeitTx::build(
            vtxo_out,
            Amount::from_sat(100_000),
            conn_out,
            Amount::from_sat(1_000),
            asp_tweaked,
            2,
        )
        .unwrap();

        // Two inputs: VTXO and connector
        assert_eq!(forfeit.tx.input.len(), 2);
        assert_eq!(forfeit.tx.input[0].previous_output, vtxo_out);
        assert_eq!(forfeit.tx.input[1].previous_output, conn_out);

        // One output to ASP
        assert_eq!(forfeit.tx.output.len(), 1);
        let expected_fee = 2 * ESTIMATED_FORFEIT_VSIZE;
        assert_eq!(forfeit.asp_output_amount.to_sat(), 101_000 - expected_fee);
    }

    #[test]
    fn test_build_forfeit_tx_fee_exceeds_amount() {
        let (_kp, _asp_pk, asp_tweaked) = test_keypair();
        let result = ForfeitTx::build(
            dummy_outpoint(1),
            Amount::from_sat(100),
            dummy_outpoint(2),
            Amount::from_sat(50),
            asp_tweaked,
            10, // 10 * 170 = 1700 > 150
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            ForfeitError::FeeExceedsAmount { .. } => {}
            e => panic!("Expected FeeExceedsAmount, got: {e:?}"),
        }
    }

    #[test]
    fn test_forfeit_txid_is_deterministic() {
        let (_kp, _asp_pk, asp_tweaked) = test_keypair();
        let f1 = ForfeitTx::build(
            dummy_outpoint(1),
            Amount::from_sat(100_000),
            dummy_outpoint(2),
            Amount::from_sat(1_000),
            asp_tweaked,
            1,
        )
        .unwrap();
        let f2 = ForfeitTx::build(
            dummy_outpoint(1),
            Amount::from_sat(100_000),
            dummy_outpoint(2),
            Amount::from_sat(1_000),
            asp_tweaked,
            1,
        )
        .unwrap();
        assert_eq!(f1.txid(), f2.txid());
    }

    #[test]
    fn test_verify_valid_signature() {
        let secp = Secp256k1::new();
        let (vtxo_kp, vtxo_pk, _vtxo_tweaked) = test_keypair();
        let (_asp_kp, _asp_pk, asp_tweaked) = test_keypair();

        let vtxo_amount = Amount::from_sat(100_000);
        let connector_amount = Amount::from_sat(1_000);

        let forfeit = ForfeitTx::build(
            dummy_outpoint(1),
            vtxo_amount,
            dummy_outpoint(2),
            connector_amount,
            asp_tweaked,
            1,
        )
        .unwrap();

        // Compute sighash and sign.
        // Use dangerous_assume_tweaked to match what verify_vtxo_signature uses internally —
        // the VTXO key is stored and verified as a raw x-only key treated as-if-tweaked.
        let vtxo_script = ScriptBuf::new_p2tr_tweaked(
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(vtxo_pk),
        );
        let connector_script = ScriptBuf::new_p2tr_tweaked(asp_tweaked);
        let prevouts = vec![
            TxOut {
                value: vtxo_amount,
                script_pubkey: vtxo_script,
            },
            TxOut {
                value: connector_amount,
                script_pubkey: connector_script,
            },
        ];

        let mut cache = SighashCache::new(&forfeit.tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &vtxo_kp);

        // Verify
        let valid = forfeit
            .verify_vtxo_signature(&sig, &vtxo_pk, vtxo_amount, connector_amount)
            .unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_tampered_signature() {
        let secp = Secp256k1::new();
        let (vtxo_kp, vtxo_pk, _vtxo_tweaked) = test_keypair();
        let (_asp_kp, _asp_pk, asp_tweaked) = test_keypair();

        let vtxo_amount = Amount::from_sat(100_000);
        let connector_amount = Amount::from_sat(1_000);

        let forfeit = ForfeitTx::build(
            dummy_outpoint(1),
            vtxo_amount,
            dummy_outpoint(2),
            connector_amount,
            asp_tweaked,
            1,
        )
        .unwrap();

        // Sign a different message
        let wrong_msg = Message::from_digest([0xAA; 32]);
        let bad_sig = secp.sign_schnorr(&wrong_msg, &vtxo_kp);

        let valid = forfeit
            .verify_vtxo_signature(&bad_sig, &vtxo_pk, vtxo_amount, connector_amount)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_pubkey() {
        let secp = Secp256k1::new();
        let (vtxo_kp, _vtxo_pk, vtxo_tweaked) = test_keypair();
        let (_asp_kp, _asp_pk, asp_tweaked) = test_keypair();
        let (_other_kp, other_pk, _other_tweaked) = test_keypair();

        let vtxo_amount = Amount::from_sat(100_000);
        let connector_amount = Amount::from_sat(1_000);

        let forfeit = ForfeitTx::build(
            dummy_outpoint(1),
            vtxo_amount,
            dummy_outpoint(2),
            connector_amount,
            asp_tweaked,
            1,
        )
        .unwrap();

        // Sign correctly but verify with wrong pubkey
        let vtxo_script = ScriptBuf::new_p2tr_tweaked(vtxo_tweaked);
        let connector_script = ScriptBuf::new_p2tr_tweaked(asp_tweaked);
        let prevouts = vec![
            TxOut {
                value: vtxo_amount,
                script_pubkey: vtxo_script,
            },
            TxOut {
                value: connector_amount,
                script_pubkey: connector_script,
            },
        ];
        let mut cache = SighashCache::new(&forfeit.tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &vtxo_kp);

        // Verify with a different pubkey → should fail
        let valid = forfeit
            .verify_vtxo_signature(&sig, &other_pk, vtxo_amount, connector_amount)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_signed_forfeit_tx() {
        let secp = Secp256k1::new();
        let (vtxo_kp, _vtxo_pk, _vtxo_tweaked) = test_keypair();
        let (_asp_kp, _asp_pk, asp_tweaked) = test_keypair();

        let forfeit = ForfeitTx::build(
            dummy_outpoint(1),
            Amount::from_sat(100_000),
            dummy_outpoint(2),
            Amount::from_sat(1_000),
            asp_tweaked,
            1,
        )
        .unwrap();

        let msg = Message::from_digest([0x42; 32]);
        let sig = secp.sign_schnorr(&msg, &vtxo_kp);

        let signed = SignedForfeitTx {
            forfeit_tx: forfeit,
            vtxo_signature: sig,
        };
        // Just verify it compiles and is accessible
        assert_eq!(signed.forfeit_tx.tx.input.len(), 2);
    }
}
