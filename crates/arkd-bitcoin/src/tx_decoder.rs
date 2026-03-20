//! Bitcoin transaction / PSBT decoder.
//!
//! Provides [`BitcoinTxDecoder`] which can parse hex-encoded PSBTs or raw
//! transactions using `rust-bitcoin`.

use bitcoin::consensus::Decodable;
use bitcoin::Transaction;

/// A decoder that parses hex-encoded PSBTs or raw Bitcoin transactions.
///
/// The `TxDecoder` trait implementation lives in
/// `arkd_core::tx_decoder_impl` to avoid a circular dependency.
#[derive(Debug, Clone, Default)]
pub struct BitcoinTxDecoder;

impl BitcoinTxDecoder {
    /// Create a new decoder instance.
    pub fn new() -> Self {
        Self
    }

    /// Decode a hex string as either a PSBT (extracting the unsigned tx) or a
    /// raw consensus-encoded transaction.
    pub fn decode_hex(hex_str: &str) -> Result<Transaction, String> {
        let bytes =
            hex::decode(hex_str.trim()).map_err(|e| format!("invalid hex in tx payload: {e}"))?;

        // Try PSBT first.
        if let Ok(psbt) = bitcoin::psbt::Psbt::deserialize(&bytes) {
            return Ok(psbt.unsigned_tx);
        }

        // Fall back to raw transaction consensus decoding.
        let mut cursor = std::io::Cursor::new(&bytes);
        Transaction::consensus_decode(&mut cursor)
            .map_err(|e| format!("failed to decode as PSBT or raw transaction: {e}"))
    }
}
