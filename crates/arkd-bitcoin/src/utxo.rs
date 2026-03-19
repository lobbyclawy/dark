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
        let mut sorted_utxos: Vec<_> = utxos.to_vec();
        sorted_utxos.sort_by_key(|u| std::cmp::Reverse(u.value()));

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
    /// Reference: <https://murch.one/wp-content/uploads/2016/11/erhardt2016coinselection.pdf>
    ///
    /// The algorithm performs depth-first search with backtracking to find a
    /// selection that either exactly matches the target (no change output) or
    /// minimizes "waste" (excess value that would become change).
    ///
    /// # Parameters
    /// - `utxos`: Available UTXOs to select from
    /// - `target`: Target amount to send (excluding fees)
    /// - `fee`: Estimated base fee for the transaction
    ///
    /// # Returns
    /// A `SelectionResult` with zero or minimal change if successful.
    /// Falls back to `largest_first` if BnB fails to find a solution within
    /// the iteration limit.
    pub fn branch_and_bound(
        utxos: &[&Utxo],
        target: Amount,
        fee: Amount,
    ) -> BitcoinResult<SelectionResult> {
        branch_and_bound_with_params(utxos, target, fee, BnbParams::default())
    }

    /// Parameters for Branch and Bound coin selection.
    #[derive(Debug, Clone, Copy)]
    pub struct BnbParams {
        /// Maximum iterations before falling back to largest-first.
        /// Prevents hanging on very large UTXO sets.
        pub max_iterations: u32,
        /// The cost of creating and later spending a change output.
        /// If excess is less than this, we consider it "changeless" and
        /// allow it as waste to avoid creating a change output.
        pub cost_of_change: Amount,
    }

    impl Default for BnbParams {
        fn default() -> Self {
            Self {
                // Bitcoin Core uses 100,000 iterations
                max_iterations: 100_000,
                // Approximate cost of a P2WPKH change output: ~31 vB to create
                // + ~68 vB to spend = ~99 vB. At 10 sat/vB = 990 sats.
                // Use 1000 sats as a reasonable default.
                cost_of_change: Amount::from_sat(1_000),
            }
        }
    }

    /// Branch and bound with custom parameters.
    pub fn branch_and_bound_with_params(
        utxos: &[&Utxo],
        target: Amount,
        fee: Amount,
        params: BnbParams,
    ) -> BitcoinResult<SelectionResult> {
        let required = target + fee;

        // Quick check: if total available is less than required, fail fast
        let total_available: Amount = utxos.iter().map(|u| u.value()).sum();
        if total_available < required {
            return Err(BitcoinError::InsufficientFunds {
                required: required.to_sat(),
                available: total_available.to_sat(),
            });
        }

        // Sort UTXOs by descending value for better pruning
        let mut sorted_utxos: Vec<_> = utxos.to_vec();
        sorted_utxos.sort_by_key(|u| std::cmp::Reverse(u.value()));

        // Precompute suffix sums for upper bound pruning
        // suffix_sum[i] = sum of values from index i to end
        let mut suffix_sums: Vec<Amount> = Vec::with_capacity(sorted_utxos.len() + 1);
        suffix_sums.push(Amount::ZERO);
        for utxo in sorted_utxos.iter().rev() {
            let prev = *suffix_sums.last().unwrap();
            suffix_sums.push(prev + utxo.value());
        }
        suffix_sums.reverse();

        // BnB state
        let mut best_selection: Option<Vec<bool>> = None;
        let mut best_waste = Amount::MAX;
        let mut current_selection = vec![false; sorted_utxos.len()];
        let mut current_value = Amount::ZERO;
        let mut iterations = 0u32;

        // Depth-first search with backtracking
        let mut index = 0usize;
        let mut backtrack = false;

        while iterations < params.max_iterations {
            iterations += 1;

            if backtrack {
                // Find the last included UTXO and exclude it
                while index > 0 {
                    index -= 1;
                    if current_selection[index] {
                        current_selection[index] = false;
                        current_value -= sorted_utxos[index].value();
                        index += 1;
                        break;
                    }
                }
                if index == 0 && !current_selection.iter().any(|&x| x) {
                    // No more possibilities to explore
                    break;
                }
                backtrack = false;
                continue;
            }

            // Check if we've found a valid solution
            if current_value >= required {
                let waste = current_value - required;

                // Accept if this is an exact match (within cost_of_change)
                // or if it has less waste than our current best
                if waste <= params.cost_of_change {
                    // Perfect! Exact match (or close enough to skip change)
                    let selected = collect_selection(&sorted_utxos, &current_selection);
                    return Ok(SelectionResult {
                        selected,
                        total: current_value,
                        change: waste,
                    });
                }

                if waste < best_waste {
                    best_waste = waste;
                    best_selection = Some(current_selection.clone());
                }

                // Backtrack to find potentially better solutions
                backtrack = true;
                continue;
            }

            // If we've processed all UTXOs, backtrack
            if index >= sorted_utxos.len() {
                backtrack = true;
                continue;
            }

            // Pruning: if even including all remaining UTXOs won't reach the target, backtrack
            let remaining_sum = suffix_sums.get(index).copied().unwrap_or(Amount::ZERO);
            if current_value + remaining_sum < required {
                backtrack = true;
                continue;
            }

            // Include this UTXO
            current_selection[index] = true;
            current_value += sorted_utxos[index].value();
            index += 1;
        }

        // Return best solution found, or fall back to largest-first
        if let Some(selection) = best_selection {
            let selected = collect_selection(&sorted_utxos, &selection);
            let total: Amount = selected.iter().map(|u| u.value()).sum();
            let change = total - required;
            Ok(SelectionResult {
                selected,
                total,
                change,
            })
        } else {
            // BnB failed to find a solution within iteration limit
            // Fall back to largest-first as a safe default
            largest_first(utxos, target, fee)
        }
    }

    /// Collect selected UTXOs based on selection mask.
    fn collect_selection(utxos: &[&Utxo], selection: &[bool]) -> Vec<Utxo> {
        utxos
            .iter()
            .zip(selection.iter())
            .filter_map(|(utxo, &selected)| {
                if selected {
                    Some((*utxo).clone())
                } else {
                    None
                }
            })
            .collect()
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
        let mut sorted_utxos: Vec<_> = utxos.to_vec();
        sorted_utxos.sort_by_key(|u| u.value());

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
        let utxos = [test_utxo(10_000), test_utxo(50_000), test_utxo(20_000)];
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
        let utxos = [test_utxo(10_000)];
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
        let utxos = [test_utxo(10_000), test_utxo(50_000), test_utxo(20_000)];
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

    // ── Branch and Bound tests ─────────────────────────────────────

    fn test_utxo_with_vout(value: u64, vout: u32) -> Utxo {
        Utxo::new(
            OutPoint {
                txid: Txid::all_zeros(),
                vout,
            },
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            },
            6,
        )
    }

    #[test]
    fn test_bnb_exact_match() {
        // UTXOs that can exactly match target + fee
        let utxos = [
            test_utxo_with_vout(10_000, 0),
            test_utxo_with_vout(20_000, 1),
            test_utxo_with_vout(15_000, 2),
        ];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // Target 29k + 1k fee = 30k, which can be exactly matched by 10k + 20k
        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(29_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // Should find exact match: 10k + 20k = 30k (zero change)
        assert_eq!(result.change, Amount::ZERO);
        assert_eq!(result.total, Amount::from_sat(30_000));
    }

    #[test]
    fn test_bnb_near_exact_match() {
        // Test that BnB accepts matches within cost_of_change threshold
        let utxos = [
            test_utxo_with_vout(10_000, 0),
            test_utxo_with_vout(20_500, 1), // 500 sats over exact
            test_utxo_with_vout(50_000, 2),
        ];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // Target 29k + 1k fee = 30k
        // Best match is 10k + 20.5k = 30.5k (500 sats change, within default 1000 threshold)
        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(29_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // Should select the near-exact match (10k + 20.5k)
        assert!(result.change <= Amount::from_sat(1_000));
        assert!(result.total <= Amount::from_sat(31_000));
    }

    #[test]
    fn test_bnb_minimizes_change() {
        // When no exact match exists, BnB should minimize change
        let utxos = [
            test_utxo_with_vout(10_000, 0),
            test_utxo_with_vout(25_000, 1),
            test_utxo_with_vout(30_000, 2),
            test_utxo_with_vout(50_000, 3),
        ];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // Target 32k + 1k fee = 33k
        // Options: 10k+25k=35k (change 2k), 10k+30k=40k (change 7k), etc.
        // Best: 10k + 25k = 35k
        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(32_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // Should have minimal change
        assert!(result.change <= Amount::from_sat(10_000));
    }

    #[test]
    fn test_bnb_single_utxo_exact() {
        let utxos = [test_utxo_with_vout(50_000, 0)];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(49_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.change, Amount::ZERO);
    }

    #[test]
    fn test_bnb_insufficient_funds() {
        let utxos = [test_utxo_with_vout(10_000, 0)];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(50_000),
            Amount::from_sat(1_000),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_bnb_empty_utxos() {
        let utxos: [Utxo; 0] = [];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_bnb_prefers_fewer_utxos() {
        // BnB should prefer solutions with fewer inputs when change is similar
        let utxos = [
            test_utxo_with_vout(10_000, 0),
            test_utxo_with_vout(10_000, 1),
            test_utxo_with_vout(10_000, 2),
            test_utxo_with_vout(30_000, 3), // Single UTXO that covers target
        ];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // Target 29k + 1k = 30k
        // Option A: 30k (1 UTXO, 0 change) - exact match
        // Option B: 10k + 10k + 10k (3 UTXOs, 0 change) - exact match but more inputs
        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(29_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // BnB finds an exact match (either works, but 0 change is key)
        assert_eq!(result.change, Amount::ZERO);
    }

    #[test]
    fn test_bnb_custom_params() {
        let utxos = [
            test_utxo_with_vout(10_000, 0),
            test_utxo_with_vout(21_000, 1), // 1k over exact, but above custom threshold
        ];
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // With tight cost_of_change of 500 sats
        let params = selection::BnbParams {
            max_iterations: 100_000,
            cost_of_change: Amount::from_sat(500),
        };

        let result = selection::branch_and_bound_with_params(
            &utxo_refs,
            Amount::from_sat(29_000),
            Amount::from_sat(1_000),
            params,
        )
        .unwrap();

        // Should still find a valid selection (total >= required)
        assert!(result.total >= Amount::from_sat(30_000));
    }

    #[test]
    fn test_bnb_many_small_utxos() {
        // Test performance with many UTXOs (should complete within iteration limit)
        let utxos: Vec<_> = (0..50).map(|i| test_utxo_with_vout(1_000, i)).collect();
        let utxo_refs: Vec<_> = utxos.iter().collect();

        // Target that requires multiple small UTXOs
        let result = selection::branch_and_bound(
            &utxo_refs,
            Amount::from_sat(10_000),
            Amount::from_sat(1_000),
        )
        .unwrap();

        // Should find a valid selection
        assert!(result.total >= Amount::from_sat(11_000));
    }

    #[test]
    fn test_bnb_fallback_on_iteration_limit() {
        // With very low iteration limit, BnB should fall back to largest-first
        let utxos: Vec<_> = (0..20)
            .map(|i| test_utxo_with_vout(1_000 + i as u64, i))
            .collect();
        let utxo_refs: Vec<_> = utxos.iter().collect();

        let params = selection::BnbParams {
            max_iterations: 1, // Extremely low - will hit limit immediately
            cost_of_change: Amount::from_sat(1_000),
        };

        let result = selection::branch_and_bound_with_params(
            &utxo_refs,
            Amount::from_sat(5_000),
            Amount::from_sat(500),
            params,
        )
        .unwrap();

        // Should still return a valid result via fallback
        assert!(result.total >= Amount::from_sat(5_500));
    }
}
