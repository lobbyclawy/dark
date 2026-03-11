//! UTXO management and coin selection

use crate::error::{BitcoinError, BitcoinResult};
use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut};
use std::collections::HashMap;

/// Represents a spendable UTXO
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// The outpoint (txid + vout)
    pub outpoint: OutPoint,
    /// The transaction output
    pub txout: TxOut,
    /// Confirmation count (0 = unconfirmed)
    pub confirmations: u32,
}

impl Utxo {
    /// Create a new UTXO
    pub fn new(outpoint: OutPoint, txout: TxOut, confirmations: u32) -> Self {
        Self {
            outpoint,
            txout,
            confirmations,
        }
    }

    /// Get the value of this UTXO
    pub fn value(&self) -> Amount {
        self.txout.value
    }

    /// Get the script pubkey
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.txout.script_pubkey
    }

    /// Check if this UTXO is confirmed
    pub fn is_confirmed(&self, min_confirmations: u32) -> bool {
        self.confirmations >= min_confirmations
    }
}

/// UTXO set manager
#[derive(Debug, Default)]
pub struct UtxoSet {
    utxos: HashMap<OutPoint, Utxo>,
}

impl UtxoSet {
    /// Create a new empty UTXO set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a UTXO to the set
    pub fn add(&mut self, utxo: Utxo) {
        self.utxos.insert(utxo.outpoint, utxo);
    }

    /// Remove a UTXO from the set
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<Utxo> {
        self.utxos.remove(outpoint)
    }

    /// Get a UTXO by outpoint
    pub fn get(&self, outpoint: &OutPoint) -> Option<&Utxo> {
        self.utxos.get(outpoint)
    }

    /// Get all UTXOs
    pub fn all(&self) -> Vec<&Utxo> {
        self.utxos.values().collect()
    }

    /// Get confirmed UTXOs
    pub fn confirmed(&self, min_confirmations: u32) -> Vec<&Utxo> {
        self.utxos
            .values()
            .filter(|u| u.is_confirmed(min_confirmations))
            .collect()
    }

    /// Calculate total value
    pub fn total_value(&self) -> Amount {
        self.utxos.values().map(|u| u.value()).sum::<Amount>()
    }

    /// Calculate total confirmed value
    pub fn total_confirmed_value(&self, min_confirmations: u32) -> Amount {
        self.confirmed(min_confirmations)
            .iter()
            .map(|u| u.value())
            .sum::<Amount>()
    }
}

/// Coin selection strategies
pub mod selection {
    use super::*;

    /// Result of coin selection
    #[derive(Debug)]
    pub struct SelectionResult {
        /// Selected UTXOs
        pub selected: Vec<Utxo>,
        /// Total selected amount
        pub total: Amount,
        /// Change amount (if any)
        pub change: Amount,
    }

    /// Largest-first coin selection
    ///
    /// Selects the largest UTXOs first until the target is met.
    /// Simple but not privacy-optimal.
    pub fn largest_first(
        utxos: &[&Utxo],
        target: Amount,
        fee: Amount,
    ) -> BitcoinResult<SelectionResult> {
        let required = target + fee;
        let mut sorted_utxos: Vec<_> = utxos.iter().copied().collect();
        sorted_utxos.sort_by(|a, b| b.value().cmp(&a.value()));

        let mut selected = Vec::new();
        let mut total = Amount::ZERO;

        for utxo in sorted_utxos {
            selected.push((*utxo).clone());
            total += utxo.value();

            if total >= required {
                let change = total - required;
                return Ok(SelectionResult {
                    selected,
                    total,
                    change,
                });
            }
        }

        Err(BitcoinError::InsufficientFunds {
            required: required.to_sat(),
            available: total.to_sat(),
        })
    }

    /// Branch and bound coin selection
    ///
    /// Tries to find an exact match or minimize change.
    /// More privacy-friendly than largest-first.
    ///
    /// TODO (Issue #3): Implement actual BnB algorithm
    /// Reference: <https://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf>
    ///
    /// For now, this falls back to largest-first selection.
    pub fn branch_and_bound(
        utxos: &[&Utxo],
        target: Amount,
        fee: Amount,
    ) -> BitcoinResult<SelectionResult> {
        // Fallback to largest-first until BnB is implemented
        largest_first(utxos, target, fee)
    }

    /// Smallest-first coin selection
    ///
    /// Selects the smallest UTXOs first. Useful for consolidation.
    pub fn smallest_first(
        utxos: &[&Utxo],
        target: Amount,
        fee: Amount,
    ) -> BitcoinResult<SelectionResult> {
        let required = target + fee;
        let mut sorted_utxos: Vec<_> = utxos.iter().copied().collect();
        sorted_utxos.sort_by(|a, b| a.value().cmp(&b.value()));

        let mut selected = Vec::new();
        let mut total = Amount::ZERO;

        for utxo in sorted_utxos {
            selected.push((*utxo).clone());
            total += utxo.value();

            if total >= required {
                let change = total - required;
                return Ok(SelectionResult {
                    selected,
                    total,
                    change,
                });
            }
        }

        Err(BitcoinError::InsufficientFunds {
            required: required.to_sat(),
            available: total.to_sat(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Txid};

    fn test_utxo(value: u64) -> Utxo {
        Utxo::new(
            OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            },
            6,
        )
    }

    #[test]
    fn test_utxo_set() {
        let mut set = UtxoSet::new();
        let utxo = test_utxo(100_000);

        set.add(utxo.clone());
        assert_eq!(set.all().len(), 1);
        assert_eq!(set.total_value(), Amount::from_sat(100_000));

        set.remove(&utxo.outpoint);
        assert_eq!(set.all().len(), 0);
    }

    #[test]
    fn test_largest_first_selection() {
        let utxos = vec![test_utxo(10_000), test_utxo(50_000), test_utxo(20_000)];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::largest_first(
            &utxo_refs,
            Amount::from_sat(30_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].value(), Amount::from_sat(50_000));
        assert_eq!(result.change, Amount::from_sat(19_000));
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![test_utxo(10_000)];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::largest_first(
            &utxo_refs,
            Amount::from_sat(50_000),
            Amount::from_sat(1_000),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_smallest_first_selection() {
        let utxos = vec![test_utxo(10_000), test_utxo(50_000), test_utxo(20_000)];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::smallest_first(
            &utxo_refs,
            Amount::from_sat(25_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // Should select 10k + 20k = 30k
        assert_eq!(result.selected.len(), 2);
        assert_eq!(result.change, Amount::from_sat(4_000));
    }
}
