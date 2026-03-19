//! Fee program domain model
//!
//! Implements CEL-based fee programs that charge per-input and per-output fees.
//! Mirrors Go arkd's fee program structure.

use serde::{Deserialize, Serialize};

/// Fee program configuration (mirrors Go's CEL-based fee programs).
///
/// Each field represents a fee component in satoshis. The total intent fee
/// is computed as a linear combination of base fee plus per-input/output fees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeProgram {
    /// Satoshis per offchain input (e.g. VTXO being refreshed)
    pub offchain_input_fee: u64,
    /// Satoshis per onchain input (e.g. boarding UTXO)
    pub onchain_input_fee: u64,
    /// Satoshis per offchain output (VTXO being created)
    pub offchain_output_fee: u64,
    /// Satoshis per onchain output (on-chain exit)
    pub onchain_output_fee: u64,
    /// Base fee per intent regardless of inputs/outputs
    pub base_fee: u64,
}

impl FeeProgram {
    /// Create a fee program with all fees set to zero.
    pub fn default_zero() -> Self {
        Self {
            offchain_input_fee: 0,
            onchain_input_fee: 0,
            offchain_output_fee: 0,
            onchain_output_fee: 0,
            base_fee: 0,
        }
    }

    /// Calculate fee for an intent given input/output counts.
    ///
    /// Fee = base_fee
    ///     + offchain_input_fee × offchain_inputs
    ///     + onchain_input_fee × onchain_inputs
    ///     + offchain_output_fee × offchain_outputs
    ///     + onchain_output_fee × onchain_outputs
    pub fn calculate_intent_fee(
        &self,
        offchain_inputs: u32,
        onchain_inputs: u32,
        offchain_outputs: u32,
        onchain_outputs: u32,
    ) -> u64 {
        self.base_fee
            + self.offchain_input_fee * offchain_inputs as u64
            + self.onchain_input_fee * onchain_inputs as u64
            + self.offchain_output_fee * offchain_outputs as u64
            + self.onchain_output_fee * onchain_outputs as u64
    }
}

impl Default for FeeProgram {
    fn default() -> Self {
        Self::default_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_zero_all_fields_zero() {
        let fp = FeeProgram::default_zero();
        assert_eq!(fp.base_fee, 0);
        assert_eq!(fp.offchain_input_fee, 0);
        assert_eq!(fp.onchain_input_fee, 0);
        assert_eq!(fp.offchain_output_fee, 0);
        assert_eq!(fp.onchain_output_fee, 0);
    }

    #[test]
    fn test_calculate_intent_fee_zero_program() {
        let fp = FeeProgram::default_zero();
        assert_eq!(fp.calculate_intent_fee(5, 3, 2, 1), 0);
    }

    #[test]
    fn test_calculate_intent_fee_base_only() {
        let fp = FeeProgram {
            base_fee: 100,
            ..FeeProgram::default_zero()
        };
        assert_eq!(fp.calculate_intent_fee(0, 0, 0, 0), 100);
        assert_eq!(fp.calculate_intent_fee(5, 3, 2, 1), 100);
    }

    #[test]
    fn test_calculate_intent_fee_all_components() {
        let fp = FeeProgram {
            offchain_input_fee: 10,
            onchain_input_fee: 20,
            offchain_output_fee: 30,
            onchain_output_fee: 40,
            base_fee: 100,
        };
        // 100 + 10*2 + 20*1 + 30*3 + 40*1 = 100 + 20 + 20 + 90 + 40 = 270
        assert_eq!(fp.calculate_intent_fee(2, 1, 3, 1), 270);
    }

    #[test]
    fn test_calculate_intent_fee_single_input() {
        let fp = FeeProgram {
            offchain_input_fee: 500,
            onchain_input_fee: 1000,
            offchain_output_fee: 200,
            onchain_output_fee: 300,
            base_fee: 50,
        };
        // 50 + 500*1 + 1000*0 + 200*1 + 300*0 = 750
        assert_eq!(fp.calculate_intent_fee(1, 0, 1, 0), 750);
    }

    #[test]
    fn test_serde_roundtrip() {
        let fp = FeeProgram {
            offchain_input_fee: 10,
            onchain_input_fee: 20,
            offchain_output_fee: 30,
            onchain_output_fee: 40,
            base_fee: 100,
        };
        let json = serde_json::to_string(&fp).unwrap();
        let fp2: FeeProgram = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, fp2);
    }
}
