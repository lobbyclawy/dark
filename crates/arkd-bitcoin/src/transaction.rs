//! Transaction building and signing utilities

use crate::error::{BitcoinError, BitcoinResult};
use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, FeeRate, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

/// Transaction builder for creating Bitcoin transactions
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    version: Version,
    lock_time: LockTime,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    fee_rate: Option<FeeRate>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee_rate: None,
        }
    }

    /// Set transaction version
    pub fn version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Set lock time
    pub fn lock_time(mut self, lock_time: LockTime) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Add an input
    pub fn add_input(mut self, outpoint: OutPoint, sequence: Sequence) -> Self {
        self.inputs.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        });
        self
    }

    /// Add an output
    pub fn add_output(mut self, script_pubkey: ScriptBuf, amount: Amount) -> Self {
        self.outputs.push(TxOut {
            value: amount,
            script_pubkey,
        });
        self
    }

    /// Add output to address
    pub fn add_output_to_address(self, address: &Address, amount: Amount) -> Self {
        self.add_output(address.script_pubkey(), amount)
    }

    /// Set fee rate
    pub fn fee_rate(mut self, fee_rate: FeeRate) -> Self {
        self.fee_rate = Some(fee_rate);
        self
    }

    /// Build the transaction
    pub fn build(self) -> BitcoinResult<Transaction> {
        if self.inputs.is_empty() {
            return Err(BitcoinError::TransactionBuildError(
                "Transaction must have at least one input".to_string(),
            ));
        }

        if self.outputs.is_empty() {
            return Err(BitcoinError::TransactionBuildError(
                "Transaction must have at least one output".to_string(),
            ));
        }

        Ok(Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.inputs,
            output: self.outputs,
        })
    }

    /// Estimate transaction size in virtual bytes
    ///
    /// This uses a conservative estimate for P2WPKH inputs and outputs.
    /// For production use, implement proper weight calculation based on actual script types.
    pub fn estimate_vsize(&self) -> usize {
        // SegWit weight calculation: (base_size * 3 + total_size) / 4
        // P2WPKH input: ~68 vbytes (41 base + 27 witness)
        // P2WSH input: ~105 vbytes (41 base + 64 witness for 2-of-3 multisig)
        // P2WPKH output: 31 bytes
        // P2WSH output: 43 bytes

        let base_size = 10; // version (4) + locktime (4) + counts (2)

        // Conservative estimate: assume all inputs are P2WPKH
        let inputs_vsize = self.inputs.len() * 68;

        // Conservative estimate: assume all outputs are P2WSH (larger)
        let outputs_vsize = self.outputs.len() * 43;

        base_size + inputs_vsize + outputs_vsize
    }

    /// Calculate estimated fee
    pub fn estimate_fee(&self) -> BitcoinResult<Amount> {
        match self.fee_rate {
            Some(rate) => {
                let vsize = self.estimate_vsize() as u64;
                Ok(rate.fee_vb(vsize).ok_or_else(|| {
                    BitcoinError::TransactionBuildError("Fee calculation overflow".to_string())
                })?)
            }
            None => Err(BitcoinError::TransactionBuildError(
                "Fee rate not set".to_string(),
            )),
        }
    }
}

/// PSBT utilities
pub mod psbt {
    use super::*;
    use bitcoin::psbt::Psbt;

    /// Create a PSBT from a transaction
    pub fn from_transaction(tx: Transaction) -> Psbt {
        Psbt::from_unsigned_tx(tx).expect("Failed to create PSBT")
    }

    /// Finalize a PSBT
    pub fn finalize(psbt: &mut Psbt) -> BitcoinResult<()> {
        // TODO: Implement proper PSBT finalization
        // For now, this is a placeholder
        Ok(())
    }

    /// Extract final transaction from PSBT
    pub fn extract_tx(psbt: &Psbt) -> BitcoinResult<Transaction> {
        psbt.clone()
            .extract_tx()
            .map_err(|e| BitcoinError::PsbtError(e.to_string()))
    }
}

/// Fee estimation utilities
pub mod fee {
    use super::*;

    /// Estimate fee for a transaction given target blocks
    pub fn estimate_fee_rate(target_blocks: u16) -> BitcoinResult<FeeRate> {
        // TODO: Implement actual fee estimation via Bitcoin Core RPC
        // For now, return a simple estimate based on target
        let sat_per_vb = match target_blocks {
            1 => 50, // High priority
            3 => 20, // Medium priority
            6 => 10, // Normal priority
            _ => 5,  // Low priority
        };

        FeeRate::from_sat_per_vb(sat_per_vb)
            .ok_or_else(|| BitcoinError::TransactionBuildError("Invalid fee rate".to_string()))
    }

    /// Calculate fee for a transaction
    pub fn calculate_fee(tx: &Transaction, fee_rate: FeeRate) -> BitcoinResult<Amount> {
        let vsize = tx.vsize() as u64;
        fee_rate
            .fee_vb(vsize)
            .ok_or_else(|| BitcoinError::TransactionBuildError("Fee overflow".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_transaction_builder() {
        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };

        let builder = TransactionBuilder::new()
            .add_input(outpoint, Sequence::MAX)
            .add_output(ScriptBuf::new(), Amount::from_sat(100_000));

        let tx = builder.build().unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
    }

    #[test]
    fn test_empty_transaction_fails() {
        let builder = TransactionBuilder::new();
        assert!(builder.build().is_err());
    }

    #[test]
    fn test_fee_estimation() {
        let fee_rate = fee::estimate_fee_rate(6).unwrap();
        assert!(fee_rate.to_sat_per_vb_ceil() >= 5);
    }
}
