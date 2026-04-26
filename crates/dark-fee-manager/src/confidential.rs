//! Weight constants for confidential transactions and a small helper that
//! lowers `(inputs, outputs, fee_rate)` into a `u64` minimum fee.
//!
//! These constants calibrate `WeightBasedFeeManager`'s confidential-tx
//! scoring per ADR-0004 §"Weight estimation for confidential transactions".
//! The numbers are sourced from `docs/benchmarks/confidential-primitives.md`
//! and `docs/protocol/confidential-vtxo-schema.md`:
//!
//! - **Per-output range proof:** ~1.3 KB at the Back-Maxwell sizing
//!   (`secp256k1-zkp = 0.11`); see the bench doc's "Range proofs" table for
//!   the single-output measurement we calibrate against.
//! - **Per-output Pedersen commitment + ephemeral pubkey + owner pubkey:**
//!   33 + 33 + 33 = 99 bytes on the wire (SEC1 compressed points).
//! - **Per-output encrypted memo overhead:** ~80 bytes (varint length + AEAD
//!   ciphertext envelope per ADR-0003). Memos themselves are bounded to a
//!   small fixed cap by the schema; we charge a representative average.
//! - **Per-input nullifier:** 32 bytes plus a small per-input metadata block.
//! - **Per-tx overhead:** balance proof (65 bytes = 33 R || 32 s per
//!   `dark-confidential::balance_proof`), schema_version (varint), proto
//!   framing, and the plaintext `fee_amount` field itself.
//!
//! Per ADR-0004 the *exact* constants are an issue-#543-owned calibration;
//! the ADR pins the **interface** (counts in, `u64` out). We accept the
//! benchmarks as authoritative and round to whole vbytes.
//!
//! ## Why these constants live here, not in `dark-confidential`
//!
//! The fee-manager treats confidential-tx weight the same way it already
//! treats P2TR weight in `weight.rs`: a small table of vbyte constants per
//! input / per output / per tx. Coupling the constants to the cryptography
//! crate would force every fee-manager backend to depend on
//! `dark-confidential`; instead, the bench numbers are the source of truth
//! and any drift caught by the `confidential-primitives` regression policy
//! prompts an update here.

use async_trait::async_trait;

use dark_core::error::ArkResult;
use dark_core::ports::{FeeManager, FeeManagerService, FeeStrategy};

/// Per-confidential-tx fixed overhead in milli-vbytes.
///
/// Balance proof (65 B) + schema_version + fee_amount varint + framing.
/// Represented as 80 vbytes = 80_000 mvB.
pub const CONFIDENTIAL_TX_OVERHEAD_MVB: u64 = 80_000;

/// Per-confidential-input cost in milli-vbytes.
///
/// 32-byte nullifier + per-input proto framing + metadata block.
/// Represented as 40 vbytes = 40_000 mvB.
pub const CONFIDENTIAL_INPUT_MVB: u64 = 40_000;

/// Per-confidential-output cost in milli-vbytes.
///
/// Range proof (~1300 B at Back-Maxwell single-output sizing) +
/// commitment (33 B) + owner_pubkey (33 B) + ephemeral_pubkey (33 B) +
/// encrypted_memo envelope (~80 B) + framing.
/// Rounded to 1500 vbytes = 1_500_000 mvB.
pub const CONFIDENTIAL_OUTPUT_MVB: u64 = 1_500_000;

/// Compute the confidential-tx weight in vbytes from input and output
/// counts.
///
/// ```text
/// vbytes = ceil(
///     (overhead_mvb
///        + inputs  × per_input_mvb
///        + outputs × per_output_mvb)
///     / 1000
/// )
/// ```
///
/// Pure integer arithmetic; no floating-point. The result is the vbyte
/// count fee-rate-driven backends multiply by their `sat/vbyte` rate.
pub fn confidential_vbytes(inputs: u64, outputs: u64) -> u64 {
    let total_mvb = CONFIDENTIAL_TX_OVERHEAD_MVB
        + inputs.saturating_mul(CONFIDENTIAL_INPUT_MVB)
        + outputs.saturating_mul(CONFIDENTIAL_OUTPUT_MVB);
    total_mvb.div_ceil(1000)
}

/// Compute the minimum fee for a confidential transaction given a
/// fee-rate-providing backend (`FeeManager`) and the input/output counts.
///
/// This is the helper used by `BitcoinCoreFeeManager` and
/// `MempoolSpaceFeeManager`'s `FeeManagerService` impls (RPC path) and by
/// any other component that needs to lower a `sat/vbyte` rate into a
/// per-confidential-tx minimum.
///
/// `min_fee_sats` clamps the result from below — backends use it to honour
/// their per-deployment minimum-fee policy.
pub async fn minimum_fee_for_rate<F: FeeManager + ?Sized>(
    fee_manager: &F,
    strategy: FeeStrategy,
    inputs: usize,
    outputs: usize,
    min_fee_sats: u64,
) -> ArkResult<u64> {
    let rate = fee_manager.estimate_fee_rate(strategy).await?;
    let vbytes = confidential_vbytes(inputs as u64, outputs as u64);
    Ok(vbytes.saturating_mul(rate).max(min_fee_sats))
}

/// `FeeManagerService` adapter that wraps any `FeeManager` (rate-only)
/// backend so it can answer `minimum_fee_confidential` queries against the
/// shared confidential-tx weight table.
///
/// Used by the RPC fee managers (`BitcoinCoreFeeManager`,
/// `MempoolSpaceFeeManager`) to honour ADR-0004 §"Constraints on #543"
/// without duplicating the weight constants in each backend.
pub struct ConfidentialFeeAdapter<F> {
    inner: F,
    strategy: FeeStrategy,
    min_fee_sats: u64,
}

impl<F> ConfidentialFeeAdapter<F> {
    /// Wrap a fee-rate provider for confidential-tx fee scoring.
    pub fn new(inner: F, strategy: FeeStrategy, min_fee_sats: u64) -> Self {
        Self {
            inner,
            strategy,
            min_fee_sats,
        }
    }

    /// Inner fee-rate provider (read-only).
    pub fn inner(&self) -> &F {
        &self.inner
    }
}

#[async_trait]
impl<F> FeeManagerService for ConfidentialFeeAdapter<F>
where
    F: FeeManager + Send + Sync,
{
    async fn boarding_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        // Adapter is dedicated to the confidential path; transparent
        // surfaces stay on the underlying transparent FeeManagerService.
        self.round_fee(1).await
    }

    async fn transfer_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        self.round_fee(1).await
    }

    async fn round_fee(&self, vtxo_count: u32) -> ArkResult<u64> {
        // Rough round-fee fallback at the underlying rate, treating each
        // VTXO as a single input/output pair. This is only used when the
        // adapter is consulted on transparent rounds; primary surface is
        // `minimum_fee_confidential` below.
        let rate = self.inner.estimate_fee_rate(self.strategy).await?;
        let vbytes = confidential_vbytes(vtxo_count as u64, vtxo_count as u64);
        Ok(vbytes.saturating_mul(rate).max(self.min_fee_sats))
    }

    async fn current_fee_rate(&self) -> ArkResult<u64> {
        self.inner.estimate_fee_rate(self.strategy).await
    }

    async fn minimum_fee_confidential(&self, inputs: usize, outputs: usize) -> ArkResult<u64> {
        minimum_fee_for_rate(
            &self.inner,
            self.strategy,
            inputs,
            outputs,
            self.min_fee_sats,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dark_core::error::ArkResult;
    use dark_core::ports::{FeeManager, FeeStrategy};

    /// Tiny `FeeManager` that returns a fixed `sat/vbyte` rate.
    struct FixedRate(u64);

    #[async_trait]
    impl FeeManager for FixedRate {
        async fn estimate_fee_rate(&self, strategy: FeeStrategy) -> ArkResult<u64> {
            match strategy {
                FeeStrategy::Custom(r) => Ok(r),
                _ => Ok(self.0),
            }
        }

        async fn invalidate_cache(&self) -> ArkResult<()> {
            Ok(())
        }
    }

    #[test]
    fn confidential_vbytes_zero_inputs_zero_outputs() {
        // overhead only: ceil(80_000 / 1000) = 80
        assert_eq!(confidential_vbytes(0, 0), 80);
    }

    #[test]
    fn confidential_vbytes_one_input_one_output() {
        // ceil((80_000 + 40_000 + 1_500_000) / 1000) = 1620
        assert_eq!(confidential_vbytes(1, 1), 1620);
    }

    #[test]
    fn confidential_vbytes_scales_linearly_with_outputs() {
        let one = confidential_vbytes(1, 1);
        let two = confidential_vbytes(1, 2);
        // Each extra output adds 1500 vbytes
        assert_eq!(two - one, 1500);
    }

    #[test]
    fn confidential_vbytes_scales_linearly_with_inputs() {
        let one = confidential_vbytes(1, 1);
        let two = confidential_vbytes(2, 1);
        // Each extra input adds 40 vbytes
        assert_eq!(two - one, 40);
    }

    #[tokio::test]
    async fn minimum_fee_for_rate_zero_rate_returns_min_floor() {
        let fm = FixedRate(0);
        let fee = minimum_fee_for_rate(&fm, FeeStrategy::Conservative, 1, 1, 546)
            .await
            .unwrap();
        // 1620 * 0 = 0, clamped to min 546
        assert_eq!(fee, 546);
    }

    #[tokio::test]
    async fn minimum_fee_for_rate_uses_rate_times_vbytes() {
        let fm = FixedRate(2);
        let fee = minimum_fee_for_rate(&fm, FeeStrategy::Conservative, 1, 1, 0)
            .await
            .unwrap();
        // 1620 * 2 = 3240
        assert_eq!(fee, 3240);
    }

    #[tokio::test]
    async fn adapter_minimum_fee_confidential_matches_helper() {
        let fm = FixedRate(5);
        let adapter = ConfidentialFeeAdapter::new(fm, FeeStrategy::Conservative, 100);
        let direct = minimum_fee_for_rate(&FixedRate(5), FeeStrategy::Conservative, 2, 3, 100)
            .await
            .unwrap();
        let via_adapter = adapter.minimum_fee_confidential(2, 3).await.unwrap();
        assert_eq!(direct, via_adapter);
    }

    #[tokio::test]
    async fn adapter_current_fee_rate_uses_strategy() {
        let adapter = ConfidentialFeeAdapter::new(FixedRate(7), FeeStrategy::Economical, 0);
        assert_eq!(adapter.current_fee_rate().await.unwrap(), 7);
    }

    #[tokio::test]
    async fn adapter_min_fee_floor_applies() {
        let adapter = ConfidentialFeeAdapter::new(FixedRate(0), FeeStrategy::Conservative, 1_234);
        assert_eq!(adapter.minimum_fee_confidential(1, 1).await.unwrap(), 1_234);
    }
}
