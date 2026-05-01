//! Regtest publication of a [`SlotAttest`] via OP_RETURN (issue #669).
//!
//! Behind the `regtest` feature flag — production publication needs
//! a different path (e.g. Taproot annex, commit-then-reveal) since
//! mainnet OP_RETURN standardness still caps single payloads. The
//! flow here is:
//!
//! 1. List unspent UTXOs from the bitcoind wallet (`listunspent`).
//! 2. Pick the first UTXO with `value ≥ attest_amount + change_dust + fee`.
//! 3. Build a single-input, two-output raw tx:
//!    - `output[0]`: 0-value OP_RETURN with
//!      [`SlotAttest::op_return_payload`] (68 B).
//!    - `output[1]`: P2WPKH change back to a fresh wallet address.
//! 4. Sign via `signrawtransactionwithwallet` (the bitcoind wallet
//!    holds the input UTXO's key).
//! 5. Broadcast via `sendrawtransaction`.
//!
//! # Deviation from issue text
//!
//! Issue #669 prescribes
//! `publish_slot_attest(client: &BitcoinCoreRpc, wallet: &DarkWallet, ...)`.
//! We drop the `&DarkWallet` parameter: bitcoind's wallet (the one
//! Nigiri seeds and the one this RPC client is bound to) holds the
//! key for the spending UTXO and signs via RPC. Pulling the BDK-based
//! `dark-wallet` crate into `dark-psar` purely for a regtest helper
//! contradicts the issue's own "lean toward focused builder"
//! direction. The integration test wires bitcoind's wallet via the
//! same `BITCOIN_RPC_URL` convention `tests/e2e_regtest.rs` already
//! uses.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::{Sequence, Version};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoincore_rpc::json::ListUnspentResultEntry;
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;

use crate::attest::SlotAttest;

/// Errors raised by [`publish_slot_attest`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PublishError {
    #[error("rpc error")]
    Rpc(#[from] bitcoincore_rpc::Error),

    #[error("no spendable UTXO with value ≥ {required} sat (largest available: {largest} sat)")]
    InsufficientFunds { required: u64, largest: u64 },

    #[error("rpc returned an unsigned tx; bitcoind wallet does not own the input")]
    SigningFailed,

    #[error("address parse error")]
    AddressParse,
}

/// Static fee floor (10_000 sats) — generous for a 1-in / 2-out P2WPKH
/// + OP_RETURN tx on regtest, where actual mining cost is `0`.
pub const STATIC_FEE_SATS: u64 = 10_000;

/// Dust floor for the change output (P2WPKH minimum economic output).
pub const CHANGE_DUST_SATS: u64 = 546;

/// Publish a [`SlotAttest`] into a regtest OP_RETURN.
///
/// # Assumptions
///
/// - The bitcoind wallet bound to `client` is loaded.
/// - The wallet holds at least one confirmed UTXO with
///   `value ≥ STATIC_FEE_SATS + CHANGE_DUST_SATS`.
/// - The caller mines the resulting transaction (e.g. via
///   `generatetoaddress`) to confirm.
pub fn publish_slot_attest(client: &Client, attest: &SlotAttest) -> Result<Txid, PublishError> {
    let utxo = pick_funded_utxo(client)?;

    let payload = attest.op_return_payload();
    let op_return_script = ScriptBuf::new_op_return(payload);

    let change_addr = client
        .get_new_address(None, None)?
        .assume_checked()
        .script_pubkey();

    let utxo_value = utxo.amount.to_sat();
    let change_value =
        utxo_value
            .checked_sub(STATIC_FEE_SATS)
            .ok_or(PublishError::InsufficientFunds {
                required: STATIC_FEE_SATS + CHANGE_DUST_SATS,
                largest: utxo_value,
            })?;

    let unsigned = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(utxo.txid, utxo.vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
            TxOut {
                value: Amount::from_sat(change_value),
                script_pubkey: change_addr,
            },
        ],
    };

    let signed = client.sign_raw_transaction_with_wallet(&unsigned, None, None)?;
    if !signed.complete {
        return Err(PublishError::SigningFailed);
    }
    let signed_tx: Transaction =
        bitcoin::consensus::deserialize(&signed.hex).map_err(|_| PublishError::SigningFailed)?;
    let txid = client.send_raw_transaction(&signed_tx)?;
    Ok(txid)
}

fn pick_funded_utxo(client: &Client) -> Result<ListUnspentResultEntry, PublishError> {
    let required = STATIC_FEE_SATS + CHANGE_DUST_SATS;
    let utxos = client.list_unspent(Some(1), None, None, None, None)?;
    let mut best_value = 0u64;
    let chosen = utxos.into_iter().find(|u| {
        let v = u.amount.to_sat();
        if v > best_value {
            best_value = v;
        }
        v >= required
    });
    chosen.ok_or(PublishError::InsufficientFunds {
        required,
        largest: best_value,
    })
}

/// Decode the `[ "PSAR" magic | 64 B sig ]` payload from a
/// transaction's OP_RETURN output, if any.
///
/// Iterates `tx.output` and returns the first OP_RETURN script whose
/// pushed data starts with [`crate::attest::OP_RETURN_MAGIC`]. Returns
/// `None` if no such output is present.
pub fn decode_slot_attest_op_return(tx: &Transaction) -> Option<Vec<u8>> {
    use bitcoin::script::Instruction;
    for out in &tx.output {
        if !out.script_pubkey.is_op_return() {
            continue;
        }
        let mut iter = out.script_pubkey.instructions();
        // Skip the OP_RETURN opcode itself.
        let _ = iter.next();
        if let Some(Ok(Instruction::PushBytes(data))) = iter.next() {
            let bytes = data.as_bytes();
            if bytes.len() == SlotAttest::OP_RETURN_SIZE
                && bytes[..4] == crate::attest::OP_RETURN_MAGIC
            {
                return Some(bytes.to_vec());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    //! Pure-Rust tests (no Nigiri / bitcoind needed). The end-to-end
    //! round-trip lives in `tests/e2e_psar_regtest.rs`.

    use super::*;
    use crate::attest::SlotAttestUnsigned;
    use bitcoin::hashes::Hash;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn make_attest(seed: u8) -> SlotAttest {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xa7u8; 32]).unwrap());
        SlotAttestUnsigned {
            slot_root: [seed; 32],
            cohort_id: [seed.wrapping_add(1); 32],
            setup_id: [seed.wrapping_add(2); 32],
            n: 12,
            k: 100,
        }
        .sign(&secp, &kp)
    }

    #[test]
    fn op_return_script_is_well_formed() {
        let attest = make_attest(0x42);
        let payload = attest.op_return_payload();
        let script = ScriptBuf::new_op_return(payload);
        assert!(script.is_op_return());
        // Total script size = 1 (OP_RETURN) + 1 (push opcode for 68 B) + 68.
        // For pushes ≤ 75 bytes, push opcode == data length byte itself.
        assert_eq!(script.len(), 70);
    }

    #[test]
    fn decode_slot_attest_op_return_round_trip() {
        let attest = make_attest(0xab);
        let payload = attest.op_return_payload();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([0u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(payload),
                },
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                },
            ],
        };
        let decoded = decode_slot_attest_op_return(&tx).expect("decoded payload present");
        assert_eq!(decoded, payload.to_vec());
    }

    #[test]
    fn decode_returns_none_when_no_op_return() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        assert!(decode_slot_attest_op_return(&tx).is_none());
    }

    #[test]
    fn decode_returns_none_for_op_return_without_magic() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([0u8; 68]),
            }],
        };
        assert!(decode_slot_attest_op_return(&tx).is_none());
    }
}
