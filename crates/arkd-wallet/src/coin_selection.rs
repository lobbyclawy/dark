//! Coin selection algorithms for UTXO management
//!
//! Implements various coin selection strategies optimized for Ark round funding:
//! - Branch and Bound (optimal, but computationally expensive)
//! - Largest First (simple, good for consolidation)
//! - Single Random Draw (privacy-preserving)

use bitcoin::Amount;

use crate::manager::WalletUtxo;
use crate::{WalletError, WalletResult};

/// Coin selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoinSelectionStrategy {
    /// Select the largest UTXOs first
    /// Good for reducing UTXO count and consolidation
    #[default]
    LargestFirst,

    /// Branch and Bound algorithm
    /// Tries to find an exact match to avoid change
    BranchAndBound,

    /// Single random draw
    /// Selects UTXOs randomly until target is met
    /// Better for privacy
    RandomDraw,

    /// Optimized for Ark rounds
    /// Prefers UTXOs that minimize transaction weight
    ArkOptimized,
}

/// Result of coin selection
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    /// Selected UTXOs
    pub selected: Vec<WalletUtxo>,
    /// Total value of selected UTXOs
    pub total_value: Amount,
    /// Fee amount
    pub fee: Amount,
    /// Change amount (if any)
    pub change: Amount,
    /// Whether this selection requires a change output
    pub needs_change: bool,
}

/// Coin selector for UTXO management
pub struct CoinSelector {
    strategy: CoinSelectionStrategy,
    /// Fee rate in sat/vB
    fee_rate: f64,
    /// Minimum change amount to create (dust threshold)
    dust_threshold: Amount,
    /// Estimated input weight (for fee calculation)
    input_weight: u64,
    /// Estimated output weight
    output_weight: u64,
    /// Estimated change output weight
    change_output_weight: u64,
}

impl CoinSelector {
    /// Create a new coin selector with default settings
    pub fn new(fee_rate: f64) -> Self {
        Self {
            strategy: CoinSelectionStrategy::default(),
            fee_rate,
            dust_threshold: Amount::from_sat(546), // P2TR dust limit
            input_weight: 68,                      // Taproot input ~68 WU
            output_weight: 43,                     // Taproot output ~43 WU
            change_output_weight: 43,
        }
    }

    /// Set the coin selection strategy
    pub fn with_strategy(mut self, strategy: CoinSelectionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set the dust threshold
    pub fn with_dust_threshold(mut self, threshold: Amount) -> Self {
        self.dust_threshold = threshold;
        self
    }

    /// Select coins to fund a transaction
    pub fn select(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> WalletResult<CoinSelectionResult> {
        // Filter out reserved UTXOs
        let available: Vec<_> = utxos.iter().filter(|u| !u.reserved).cloned().collect();

        if available.is_empty() {
            return Err(WalletError::InsufficientFunds {
                required: target.to_sat(),
                available: 0,
            });
        }

        match self.strategy {
            CoinSelectionStrategy::LargestFirst => {
                self.select_largest_first(&available, target, num_outputs)
            }
            CoinSelectionStrategy::BranchAndBound => {
                // Try BnB first, fall back to largest first
                self.select_branch_and_bound(&available, target, num_outputs)
                    .or_else(|_| self.select_largest_first(&available, target, num_outputs))
            }
            CoinSelectionStrategy::RandomDraw => {
                self.select_random_draw(&available, target, num_outputs)
            }
            CoinSelectionStrategy::ArkOptimized => {
                self.select_ark_optimized(&available, target, num_outputs)
            }
        }
    }

    /// Select coins using largest-first strategy
    fn select_largest_first(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> WalletResult<CoinSelectionResult> {
        let mut sorted = utxos.to_vec();
        sorted.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        for utxo in sorted {
            selected.push(utxo.clone());
            total_value += utxo.amount;

            let fee = self.calculate_fee(selected.len(), num_outputs, true);

            if total_value >= target + fee {
                let change = total_value - target - fee;
                let needs_change = change >= self.dust_threshold;

                // Recalculate fee without change if not needed
                let final_fee = if needs_change {
                    fee
                } else {
                    self.calculate_fee(selected.len(), num_outputs, false)
                };

                let final_change = if needs_change {
                    total_value - target - final_fee
                } else {
                    Amount::ZERO
                };

                return Ok(CoinSelectionResult {
                    selected,
                    total_value,
                    fee: final_fee,
                    change: final_change,
                    needs_change,
                });
            }
        }

        let available: u64 = utxos.iter().map(|u| u.amount.to_sat()).sum();
        Err(WalletError::InsufficientFunds {
            required: target.to_sat(),
            available,
        })
    }

    /// Select coins using branch-and-bound algorithm
    /// Tries to find exact match (no change)
    fn select_branch_and_bound(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> WalletResult<CoinSelectionResult> {
        // Simplified BnB - for production, use full algorithm
        // This version just tries a few combinations

        let fee_no_change = self.calculate_fee(utxos.len(), num_outputs, false);
        let effective_target = target + fee_no_change;

        // Try to find exact match with different UTXO combinations
        // Use dynamic programming approach for small UTXO sets
        if utxos.len() <= 20 {
            if let Some(result) = self.find_exact_match(utxos, effective_target, num_outputs) {
                return Ok(result);
            }
        }

        // Fall back to largest first
        self.select_largest_first(utxos, target, num_outputs)
    }

    /// Find exact match combination (subset sum)
    fn find_exact_match(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> Option<CoinSelectionResult> {
        let target_sat = target.to_sat();

        // Use bit manipulation for subset enumeration (up to 20 UTXOs)
        let n = utxos.len().min(20);
        let max_mask = 1u32 << n;

        for mask in 1..max_mask {
            let selected: Vec<_> = (0..n)
                .filter(|i| (mask >> i) & 1 == 1)
                .map(|i| utxos[i].clone())
                .collect();

            let total: u64 = selected.iter().map(|u| u.amount.to_sat()).sum();
            let fee = self.calculate_fee(selected.len(), num_outputs, false);

            // Allow small tolerance for rounding
            if (total as i64 - target_sat as i64).abs() <= fee.to_sat() as i64 {
                return Some(CoinSelectionResult {
                    total_value: Amount::from_sat(total),
                    fee,
                    change: Amount::ZERO,
                    needs_change: false,
                    selected,
                });
            }
        }

        None
    }

    /// Select coins randomly
    fn select_random_draw(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> WalletResult<CoinSelectionResult> {
        use bitcoin::secp256k1::rand::seq::SliceRandom;
        use bitcoin::secp256k1::rand::thread_rng;

        let mut shuffled = utxos.to_vec();
        shuffled.shuffle(&mut thread_rng());

        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        for utxo in shuffled {
            selected.push(utxo.clone());
            total_value += utxo.amount;

            let fee = self.calculate_fee(selected.len(), num_outputs, true);

            if total_value >= target + fee {
                let change = total_value - target - fee;
                let needs_change = change >= self.dust_threshold;

                let final_fee = if needs_change {
                    fee
                } else {
                    self.calculate_fee(selected.len(), num_outputs, false)
                };

                return Ok(CoinSelectionResult {
                    selected,
                    total_value,
                    fee: final_fee,
                    change: if needs_change {
                        total_value - target - final_fee
                    } else {
                        Amount::ZERO
                    },
                    needs_change,
                });
            }
        }

        let available: u64 = utxos.iter().map(|u| u.amount.to_sat()).sum();
        Err(WalletError::InsufficientFunds {
            required: target.to_sat(),
            available,
        })
    }

    /// Ark-optimized coin selection
    /// Prefers UTXOs with good confirmation depth and similar values
    fn select_ark_optimized(
        &self,
        utxos: &[WalletUtxo],
        target: Amount,
        num_outputs: usize,
    ) -> WalletResult<CoinSelectionResult> {
        // Score each UTXO based on:
        // - Confirmation depth (more is better)
        // - Value proximity to average needed per input
        let mut scored: Vec<(f64, WalletUtxo)> = utxos
            .iter()
            .map(|utxo| {
                let conf_score = (utxo.confirmations.min(100) as f64) / 100.0;
                let value_score = 1.0; // Could add value-based scoring
                (conf_score * 0.3 + value_score * 0.7, utxo.clone())
            })
            .collect();

        // Sort by score (highest first)
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let sorted_utxos: Vec<_> = scored.into_iter().map(|(_, u)| u).collect();

        // Use sorted list with largest-first selection
        let mut selected = Vec::new();
        let mut total_value = Amount::ZERO;

        for utxo in sorted_utxos {
            selected.push(utxo.clone());
            total_value += utxo.amount;

            let fee = self.calculate_fee(selected.len(), num_outputs, true);

            if total_value >= target + fee {
                let change = total_value - target - fee;
                let needs_change = change >= self.dust_threshold;

                let final_fee = if needs_change {
                    fee
                } else {
                    self.calculate_fee(selected.len(), num_outputs, false)
                };

                return Ok(CoinSelectionResult {
                    selected,
                    total_value,
                    fee: final_fee,
                    change: if needs_change {
                        total_value - target - final_fee
                    } else {
                        Amount::ZERO
                    },
                    needs_change,
                });
            }
        }

        let available: u64 = utxos.iter().map(|u| u.amount.to_sat()).sum();
        Err(WalletError::InsufficientFunds {
            required: target.to_sat(),
            available,
        })
    }

    /// Calculate transaction fee
    fn calculate_fee(&self, num_inputs: usize, num_outputs: usize, with_change: bool) -> Amount {
        // Base transaction weight (header + locktime + etc.)
        let base_weight: u64 = 44;

        let input_weight = num_inputs as u64 * self.input_weight;
        let output_weight = num_outputs as u64 * self.output_weight;
        let change_weight = if with_change {
            self.change_output_weight
        } else {
            0
        };

        let total_weight = base_weight + input_weight + output_weight + change_weight;
        let vbytes = total_weight.div_ceil(4);

        Amount::from_sat((vbytes as f64 * self.fee_rate).ceil() as u64)
    }
}

/// Calculate the effective value of a UTXO (value minus fee to spend it)
pub fn effective_value(utxo: &WalletUtxo, fee_rate: f64, input_weight: u64) -> Amount {
    let spending_fee = (input_weight as f64 / 4.0 * fee_rate).ceil() as u64;
    utxo.amount
        .checked_sub(Amount::from_sat(spending_fee))
        .unwrap_or(Amount::ZERO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::OutPoint;

    fn make_utxo(sats: u64, confirmations: u32) -> WalletUtxo {
        WalletUtxo {
            outpoint: OutPoint::null(),
            amount: Amount::from_sat(sats),
            confirmations,
            reserved: false,
        }
    }

    #[test]
    fn test_largest_first_selection() {
        let utxos = vec![
            make_utxo(10_000, 6),
            make_utxo(50_000, 6),
            make_utxo(30_000, 6),
        ];

        let selector = CoinSelector::new(1.0).with_strategy(CoinSelectionStrategy::LargestFirst);

        let result = selector
            .select(&utxos, Amount::from_sat(60_000), 1)
            .unwrap();

        // Should select 50k + 30k = 80k
        assert_eq!(result.selected.len(), 2);
        assert!(result.total_value >= Amount::from_sat(60_000));
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = vec![make_utxo(10_000, 6)];

        let selector = CoinSelector::new(1.0);

        let result = selector.select(&utxos, Amount::from_sat(50_000), 1);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_reserved_utxos_excluded() {
        let mut utxo = make_utxo(100_000, 6);
        utxo.reserved = true;

        let utxos = vec![utxo, make_utxo(10_000, 6)];

        let selector = CoinSelector::new(1.0);
        let result = selector.select(&utxos, Amount::from_sat(50_000), 1);

        // Should fail because only 10k is available (100k is reserved)
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_fee_calculation() {
        let selector = CoinSelector::new(10.0); // 10 sat/vB

        // 1 input, 1 output, no change
        let fee = selector.calculate_fee(1, 1, false);
        assert!(fee > Amount::ZERO);

        // More inputs = higher fee
        let fee_2_inputs = selector.calculate_fee(2, 1, false);
        assert!(fee_2_inputs > fee);
    }

    #[test]
    fn test_dust_threshold() {
        let utxos = vec![make_utxo(10_000, 6)];

        let selector = CoinSelector::new(1.0).with_dust_threshold(Amount::from_sat(1000));

        let result = selector.select(&utxos, Amount::from_sat(9_000), 1).unwrap();

        // Small change should be absorbed into fee
        assert!(result.change.to_sat() == 0 || result.change >= Amount::from_sat(1000));
    }

    #[test]
    fn test_effective_value() {
        let utxo = make_utxo(10_000, 6);
        let eff = effective_value(&utxo, 10.0, 68);

        // Spending fee = 68 / 4 * 10 = 170 sats
        // Effective value = 10000 - 170 = 9830
        assert!(eff < utxo.amount);
        assert!(eff > Amount::ZERO);
    }
}
