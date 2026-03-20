//! `TxDecoder` trait implementation for `dark_bitcoin::BitcoinTxDecoder`.
//!
//! Bridges the standalone `BitcoinTxDecoder` from `dark-bitcoin` to the
//! `TxDecoder` trait defined in `dark-core::ports`.

use async_trait::async_trait;

use crate::error::{ArkError, ArkResult};
use crate::ports::{DecodedTx, DecodedTxIn, DecodedTxOut, TxDecoder};

use dark_bitcoin::tx_decoder::BitcoinTxDecoder;

#[async_trait]
impl TxDecoder for BitcoinTxDecoder {
    async fn decode_tx(&self, tx: &str) -> ArkResult<DecodedTx> {
        let transaction = BitcoinTxDecoder::decode_hex(tx).map_err(ArkError::Internal)?;

        let txid = transaction.compute_txid().to_string();

        let inputs = transaction
            .input
            .iter()
            .map(|inp| DecodedTxIn {
                txid: inp.previous_output.txid.to_string(),
                vout: inp.previous_output.vout,
            })
            .collect();

        let outputs = transaction
            .output
            .iter()
            .map(|out| DecodedTxOut {
                amount: out.value.to_sat(),
                pk_script: out.script_pubkey.to_bytes(),
            })
            .collect();

        Ok(DecodedTx {
            txid,
            inputs,
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::Encodable;
    use bitcoin::psbt::Psbt;
    use bitcoin::{
        absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };

    /// Build a minimal valid transaction for testing.
    fn sample_tx() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: "abababababababababababababababababababababababababababababababab"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x00, 0x14, 0xaa, 0xbb, 0xcc]),
            }],
        }
    }

    #[tokio::test]
    async fn decode_raw_transaction() {
        let tx = sample_tx();
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf).unwrap();
        let hex_str = hex::encode(&buf);

        let decoder = BitcoinTxDecoder::new();
        let decoded = decoder.decode_tx(&hex_str).await.unwrap();

        assert_eq!(decoded.txid, tx.compute_txid().to_string());
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.inputs[0].vout, 0);
        assert_eq!(decoded.outputs.len(), 1);
        assert_eq!(decoded.outputs[0].amount, 50_000);
    }

    #[tokio::test]
    async fn decode_psbt() {
        let tx = sample_tx();
        let psbt = Psbt::from_unsigned_tx(tx.clone()).expect("valid unsigned tx");
        let psbt_bytes = psbt.serialize();
        let hex_str = hex::encode(&psbt_bytes);

        let decoder = BitcoinTxDecoder::new();
        let decoded = decoder.decode_tx(&hex_str).await.unwrap();

        assert_eq!(decoded.txid, tx.compute_txid().to_string());
        assert_eq!(decoded.inputs.len(), 1);
        assert_eq!(decoded.outputs.len(), 1);
    }

    #[tokio::test]
    async fn decode_invalid_hex_returns_error() {
        let decoder = BitcoinTxDecoder::new();
        let result = decoder.decode_tx("not-valid-hex!").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn decode_garbage_bytes_returns_error() {
        let decoder = BitcoinTxDecoder::new();
        let result = decoder.decode_tx(&hex::encode(b"garbage")).await;
        assert!(result.is_err());
    }
}
