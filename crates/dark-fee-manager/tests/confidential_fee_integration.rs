//! Integration test for ADR-0004 §"Constraints on #543" / acceptance
//! criterion 2:
//!
//! > Provide an integration test that submits a confidential tx with
//! > `fee_amount = operator_min_fee − 1` (rejected) and another with
//! > `fee_amount = operator_min_fee` (accepted).
//!
//! The end-to-end submission pipeline (gRPC handler, balance-proof
//! verification, nullifier set update) is owned by issues #538 and #542 and
//! lives in `dark-api` / `dark-confidential`. From the *fee-manager* side
//! the contract this PR (#543) freezes is narrower:
//!
//! 1. `FeeManagerService::minimum_fee_confidential(inputs, outputs)`
//!    returns a single `u64` minimum fee derived from confidential-tx
//!    counts only — no plaintext amounts, no tuple, no parallel trait.
//! 2. The validator's fee gate (per the pseudocode in ADR-0004) compares
//!    `tx.fee_amount` against that `u64` and short-circuits on failure.
//!
//! The tests below exercise that contract for every #543-wired backend
//! (Static / Weight / RPC-adapter / CEL) plus the trait default that
//! `NoopFeeManager` falls into.

use async_trait::async_trait;

use dark_core::domain::FeeProgram;
use dark_core::error::ArkResult;
use dark_core::ports::{FeeManager, FeeManagerService, FeeStrategy, NoopFeeManager};
use dark_fee_manager::confidential::ConfidentialFeeAdapter;
use dark_fee_manager::{SimpleFeeManager, WeightBasedFeeManager};

/// Minimal `ConfidentialTransaction` mirror sufficient for fee-gate tests.
///
/// Mirrors the proto field shape (`fee_amount: u64`) and counts but stops
/// short of the cryptographic payload, which lives in #538 territory.
struct FakeConfidentialTransaction {
    fee_amount: u64,
    inputs: usize,
    outputs: usize,
}

impl FakeConfidentialTransaction {
    fn new(fee_amount: u64, inputs: usize, outputs: usize) -> Self {
        Self {
            fee_amount,
            inputs,
            outputs,
        }
    }
}

/// Verdict returned by the fee gate.
///
/// Mirrors `SubmitConfidentialTransactionResponse.{accepted, Error}` from
/// `proto/ark/v1/confidential_tx.proto` (#537) without pulling in the
/// proto bindings.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accepted,
    /// Maps to `Error::ERROR_FEE_TOO_LOW` on the wire.
    RejectedFeeTooLow {
        fee: u64,
        min: u64,
    },
}

/// Implements the fee gate from ADR-0004 §"Validation pseudocode" steps
/// (1)-(3): parse, sanity cap (skipped here, owned by #538), minimum-fee
/// gate.
///
/// The gate consults a `FeeManagerService` for the per-tx minimum and
/// compares it against `tx.fee_amount` exactly once (per ADR-0004 §"#538
/// MUST NOT" rule "Read `tx.fee_amount` more than once").
async fn fee_gate(
    fee_manager: &dyn FeeManagerService,
    tx: &FakeConfidentialTransaction,
) -> ArkResult<Verdict> {
    let fee = tx.fee_amount;
    let min = fee_manager
        .minimum_fee_confidential(tx.inputs, tx.outputs)
        .await?;
    if fee < min {
        Ok(Verdict::RejectedFeeTooLow { fee, min })
    } else {
        Ok(Verdict::Accepted)
    }
}

/// Asserts the rejected/accepted pair for a single fee-manager backend.
///
/// `tx_inputs` and `tx_outputs` must match what the gate sees on the wire;
/// `min - 1` is rejected, `min` is accepted, exactly per ADR-0004's
/// acceptance criterion 2.
async fn assert_rejected_then_accepted(
    fee_manager: &dyn FeeManagerService,
    tx_inputs: usize,
    tx_outputs: usize,
) {
    let min = fee_manager
        .minimum_fee_confidential(tx_inputs, tx_outputs)
        .await
        .expect("minimum_fee_confidential should succeed");
    assert!(
        min > 0,
        "test prerequisite: backend must publish a non-zero minimum so \
         (min - 1) is well-defined"
    );

    // (a) fee = min - 1 -> rejected with FEE_TOO_LOW
    let too_low = FakeConfidentialTransaction::new(min - 1, tx_inputs, tx_outputs);
    let verdict = fee_gate(fee_manager, &too_low).await.unwrap();
    assert_eq!(
        verdict,
        Verdict::RejectedFeeTooLow { fee: min - 1, min },
        "fee_amount = min - 1 must be rejected with FEE_TOO_LOW"
    );

    // (b) fee = min -> accepted
    let exact = FakeConfidentialTransaction::new(min, tx_inputs, tx_outputs);
    let verdict = fee_gate(fee_manager, &exact).await.unwrap();
    assert_eq!(
        verdict,
        Verdict::Accepted,
        "fee_amount = min must be accepted"
    );

    // (c) fee = min + 1 -> still accepted (gate is `>=`, not `==`)
    let above = FakeConfidentialTransaction::new(min + 1, tx_inputs, tx_outputs);
    let verdict = fee_gate(fee_manager, &above).await.unwrap();
    assert_eq!(verdict, Verdict::Accepted);
}

// -- Static path -------------------------------------------------------------

#[tokio::test]
async fn confidential_fee_gate_static_rejects_below_min_accepts_at_min() {
    // SimpleFeeManager (Static): flat fee rate × confidential vbytes.
    // 5 sat/vB at 1 input, 1 output -> 1620 vbytes -> 8100 sats min.
    let fm = SimpleFeeManager::new(5, 0);
    assert_rejected_then_accepted(&fm, 1, 1).await;
}

#[tokio::test]
async fn confidential_fee_gate_static_scales_with_outputs() {
    // Verify the gate threshold grows with output count, exercising the
    // count-based scoring required by ADR-0004 (no amounts).
    let fm = SimpleFeeManager::new(5, 0);
    let one = fm.minimum_fee_confidential(1, 1).await.unwrap();
    let three = fm.minimum_fee_confidential(1, 3).await.unwrap();
    assert!(three > one);
    assert_rejected_then_accepted(&fm, 1, 3).await;
}

// -- Weight path -------------------------------------------------------------

#[tokio::test]
async fn confidential_fee_gate_weight_rejects_below_min_accepts_at_min() {
    // WeightBasedFeeManager: confidential weight constants × fee rate.
    let fm = WeightBasedFeeManager::new(2, 0);
    assert_rejected_then_accepted(&fm, 1, 1).await;
}

#[tokio::test]
async fn confidential_fee_gate_weight_realistic_round() {
    // 4 nullifiers, 4 outputs at 5 sat/vB — typical mid-sized confidential
    // round shape from the m3 protocol design.
    let fm = WeightBasedFeeManager::new(5, 0);
    assert_rejected_then_accepted(&fm, 4, 4).await;
}

// -- RPC path (Bitcoin Core / mempool.space) --------------------------------

/// Minimal `FeeManager` test double that returns a fixed `sat/vbyte` rate.
///
/// Stands in for `BitcoinCoreFeeManager` and `MempoolSpaceFeeManager` in
/// the unit-test domain — both lower their RPC-derived rate into the same
/// `ConfidentialFeeAdapter` machinery, so the gate behaviour is identical
/// regardless of which RPC source backed the rate.
struct StubRpcRate(u64);

#[async_trait]
impl FeeManager for StubRpcRate {
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

#[tokio::test]
async fn confidential_fee_gate_rpc_rejects_below_min_accepts_at_min() {
    // RPC (BitcoinCore / mempool.space) is wrapped via the adapter so the
    // same fee-gate semantics apply.
    let fm = ConfidentialFeeAdapter::new(StubRpcRate(3), FeeStrategy::Conservative, 0);
    assert_rejected_then_accepted(&fm, 1, 1).await;
}

// -- CEL path ----------------------------------------------------------------

/// Wraps a `FeeProgram` (CEL surface) as a `FeeManagerService` so it
/// participates in the same fee gate as the other backends.
///
/// Per ADR-0004 §"Privacy boundary for CEL" the program is evaluated
/// against **counts only**. This wrapper enforces that contract by
/// construction: it never receives amounts, so it cannot leak them.
struct CelFeeService {
    program: FeeProgram,
}

#[async_trait]
impl FeeManagerService for CelFeeService {
    async fn boarding_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        Ok(self.program.base_fee)
    }
    async fn transfer_fee(&self, _amount_sats: u64) -> ArkResult<u64> {
        Ok(self.program.base_fee)
    }
    async fn round_fee(&self, _vtxo_count: u32) -> ArkResult<u64> {
        Ok(self.program.base_fee)
    }
    async fn current_fee_rate(&self) -> ArkResult<u64> {
        Ok(1)
    }
    async fn minimum_fee_confidential(&self, inputs: usize, outputs: usize) -> ArkResult<u64> {
        // CEL path: counts only — no amounts.
        Ok(self
            .program
            .calculate_confidential_intent_fee(inputs as u32, outputs as u32))
    }
}

#[tokio::test]
async fn confidential_fee_gate_cel_rejects_below_min_accepts_at_min() {
    let fm = CelFeeService {
        program: FeeProgram {
            offchain_input_fee: 50,
            offchain_output_fee: 200,
            base_fee: 100,
            ..FeeProgram::default_zero()
        },
    };
    // Expected min for (2, 3): 100 + 50*2 + 200*3 = 800
    assert_eq!(fm.minimum_fee_confidential(2, 3).await.unwrap(), 800);
    assert_rejected_then_accepted(&fm, 2, 3).await;
}

#[tokio::test]
async fn confidential_fee_gate_cel_no_amount_passthrough() {
    // Sentinel: CEL's onchain_*_fee rates are deliberately huge; the
    // confidential surface MUST ignore them (see ADR-0004 §"Privacy
    // boundary for CEL" — confidential VTXOs are off-chain by
    // construction).
    let fm = CelFeeService {
        program: FeeProgram {
            offchain_input_fee: 10,
            offchain_output_fee: 20,
            onchain_input_fee: u64::MAX / 2,
            onchain_output_fee: u64::MAX / 2,
            base_fee: 0,
        },
    };
    let min = fm.minimum_fee_confidential(2, 2).await.unwrap();
    // 10*2 + 20*2 = 60; if onchain rates leaked in we'd overflow long
    // before getting here.
    assert_eq!(min, 60);
}

// -- Trait default (NoopFeeManager) -----------------------------------------

#[tokio::test]
async fn confidential_fee_gate_noop_accepts_zero_fee() {
    // NoopFeeManager (test deployments / fee-free configurations) lives
    // on the trait default and returns 0 — every confidential tx passes
    // the gate. This is the explicit `fee_amount = 0`,
    // `operator_min_fee = 0` row in ADR-0004 §"Edge-case matrix".
    let fm = NoopFeeManager;
    let min = fm.minimum_fee_confidential(1, 1).await.unwrap();
    assert_eq!(min, 0);

    let zero = FakeConfidentialTransaction::new(0, 1, 1);
    let verdict = fee_gate(&fm, &zero).await.unwrap();
    assert_eq!(verdict, Verdict::Accepted);
}
