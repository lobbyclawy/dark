# Dark Server — Go E2E Gap Analysis

**Date**: 2026-03-23  
**Dark commit**: current HEAD  
**Test file**: `arkd-go/internal/test/e2e/e2e_test.go`

---

## Summary

| Status | Count |
|--------|-------|
| **Passing** | 0 |
| **Failing** | All tests |
| **Root causes** | 3 blocking + several secondary |

All e2e tests fail. There are **3 root causes** that account for all failures, listed in priority order. Fixing them in sequence will progressively unlock more tests.

---

## Root Cause #1: Empty witness on server wallet fee input (BLOCKER)

**Affects**: ALL tests that settle/board (TestBatchSession/refresh_vtxos and everything downstream)

**What happens**: The round completes successfully — intents register, tree signing works, forfeit txs are signed. But the commitment tx fails to broadcast because **input 2 (the server's BDK wallet UTXO for fees) has an empty witness**.

**Evidence from logs**:
```
BDK WalletManager sign result per input input_idx=2 has_tap_key_sig=false tap_script_sigs=0 has_internal_key=true tap_key_origins=1 has_final_witness=false

mempool-script-verify-flag-failed (Witness program was passed an empty witness), input 2
```

**Root cause**: BDK wallet `sign()` populates `tap_key_origins` and `internal_key` on the fee input but NOT `tap_key_sig`. The `finalize_and_extract` step then produces an empty witness for this input. This happens because:
1. BDK wallet was given the PSBT with its input already filled with `witness_utxo`, but the signing method doesn't complete the taproot key-path spend
2. The server adds the fee input after the boarding inputs are already set up, but the BDK signing context doesn't have the right sighash preimage data or the PSBT input fields aren't complete enough for BDK to auto-sign

**Fix required**: In the commitment tx finalization path (`dark-core/src/application.rs` or `dark-wallet/src/manager.rs`), ensure the server wallet's fee input gets a proper taproot key-path signature before finalization. Either:
- Set the correct `tap_internal_key` + `tap_key_origins` fields before calling BDK sign, OR
- Manually sign the fee input with the server's key using schnorr signing, OR
- Call BDK wallet's sign method with the complete PSBT fields that BDK needs to produce `tap_key_sig`

**Complexity**: Medium  
**Files**: `crates/dark-wallet/src/manager.rs`, `crates/dark-core/src/application.rs`

---

## Root Cause #2: Admin Note endpoint not implemented

**Affects**: ALL tests that use `faucetOffchain()` — which is ~90% of tests:
- TestBatchSession/redeem_notes
- TestUnilateralExit/leaf_vtxo  
- TestCollaborativeExit/* (all subtests)
- TestOffchainTx/* (all subtests)
- TestDelegateRefresh
- TestSendToCLTVMultisigClosure
- TestSendToConditionMultisigClosure
- TestReactToFraud/* (all subtests)
- TestSweep/checkpoint
- TestSweep/unrolled_batch
- TestFee
- TestAsset/* (all subtests)
- TestIntent/* (all subtests)
- TestBan/* (all subtests)
- TestTxListenerChurn
- TestEventListenerChurn

**What happens**: `POST /v1/admin/note` returns `{"code":12,"error":"CreateNote not yet implemented — requires NoteService"}`. The Go test's `generateNote()` panics with index out of range because the response has no `notes` array.

**Root cause**: The admin note creation endpoint is stubbed. The `NoteService` that creates bearer notes hasn't been implemented.

**Fix required**: Implement `CreateNote` admin RPC. A note is a server-signed bearer token that entitles the holder to a specified amount of sats in a batch round (like a coupon). The server needs to:
1. Generate a random note ID / secret
2. Sign it with the server key
3. Store it in a note registry
4. Return the encoded note string
5. When `RedeemNotes` is called, validate the note, mark it consumed, and create a VTXO for the redeemer

**Complexity**: High (requires new service + storage + redemption flow)  
**Files**: `crates/dark-api/src/grpc/admin_service.rs`, `crates/dark-api/src/grpc/ark_service.rs` (RedeemNotes), new `crates/dark-core/src/note_service.rs`

---

## Root Cause #3: Boarding UTXOs not marked as consumed after settle

**Affects**: TestBatchSession/refresh_vtxos (final assertion), TestFee (final assertion)

**What happens**: After a successful settle (assuming Root Cause #1 is fixed), the test checks that `LockedAmount` is empty. But the boarding UTXOs still show as locked because they aren't marked as consumed/spent in the VTXO store after the commitment tx includes them.

**Evidence**: 
```
Error: Should be empty, but was [{2026-03-24T12:59:01-05:00 21000}]
```

**Root cause**: When the round finalizes and the commitment tx is broadcast, the server doesn't update the status of boarding UTXOs (which were spent as inputs) in the indexer/VTXO store. The client queries its boarding address UTXOs via esplora and still sees them as unspent (since the commitment tx hasn't been confirmed yet) or the indexer doesn't track boarding UTXO consumption.

**Fix required**: After successfully broadcasting the commitment tx, mark the boarding UTXOs as spent/consumed in the VTXO indexer so that `GetVtxos` for the boarding address script returns them with `spent=true` status.

**Complexity**: Medium  
**Files**: `crates/dark-core/src/application.rs`, `crates/dark-core/src/boarding.rs`, `crates/dark-db/src/repos/boarding_repo.rs`

---

## Secondary Issues (will become visible after fixing root causes)

### 4. Admin Intent Fees API format mismatch

**Affects**: TestFee

**What happens**: `GET /v1/admin/intentFees` returns `{"fees":{"baseFeeSats":"0","feeRatePpm":"0"}}` but the Go tests expect `{"fees":{"offchainInputFee":"...","onchainInputFee":"...","offchainOutputFee":"...","onchainOutputFee":"..."}}`.

Also, `POST /v1/admin/intentFees` returns "not implemented".

**Fix required**: Implement the 4-program fee model matching the Go server's intent fee system: separate fee programs for offchain input, onchain input, offchain output, onchain output. Each is an expression string evaluated per-intent.

**Complexity**: Medium-High  
**Files**: `crates/dark-api/src/grpc/admin_service.rs`, `crates/dark-core/src/domain/fee.rs`

### 5. Admin Sweep endpoint returns no txid

**Affects**: TestSweep/force_by_admin

**What happens**: `POST /v1/admin/sweep` returns `{"recoveryTxid":"","sweepTxid":"","sweptCount":0}` with empty txid even when there are expired batches.

**Fix required**: The sweep endpoint needs to actually build and broadcast a sweep transaction for specified commitment txids, then return the txid.

**Complexity**: Medium  
**Files**: `crates/dark-api/src/grpc/admin_service.rs`, `crates/dark-core/src/sweep.rs`

### 6. Asset RPCs are stubs

**Affects**: TestAsset/* (all subtests: transfer_and_renew, issuance/*, reissuance, burn, unroll, asset_and_subdust, asset_subdust_settle)

**What happens**: IssueAsset, ReissueAsset, BurnAsset return fake stub values like `stub-asset-5000-`. RedeemNotes also returns `stub-redeem-notes-tx`.

**Fix required**: Full implementation of the asset lifecycle (issuance, transfer, reissuance, burn) with proper VTXO tracking and script validation.

**Complexity**: Very High  
**Files**: `crates/dark-api/src/grpc/ark_service.rs`, `crates/dark-core/src/domain/asset.rs`

### 7. Docker-based restartArkd() won't work

**Affects**: TestSweep/with_arkd_restart

**What happens**: The Go test calls `docker container stop arkd` / `docker container start arkd` which won't work with our native binary setup.

**Fix required**: Either adapt the test or implement a server restart mechanism via admin API (lock wallet + unlock).

**Complexity**: Low (test infrastructure, not server code)

### 8. Collaborative Exit implementation may be incomplete

**Affects**: TestCollaborativeExit/* (once notes work for fauceting)

**Status**: Untested because faucetOffchain fails first. The endpoint exists (`CollaborativeExit` is implemented in `ark_service.rs`) but may have issues with:
- Proper validation of boarding inputs in exit requests
- Change VTXO creation

**Complexity**: Unknown until root causes are fixed

### 9. SubmitTx / FinalizeTx may have issues

**Affects**: TestOffchainTx/concurrent_submit_txs, TestOffchainTx/finalize_pending_tx, TestOffchainTx/too_many_op_return_outputs, TestOffchainTx/invalid_tx_size

**Status**: Untested because faucetOffchain fails first. The endpoints exist but validation rules (OP_RETURN limits, tx size limits, double-spend detection) may not be fully implemented.

**Complexity**: Unknown until root causes are fixed

### 10. Ban system may be incomplete

**Affects**: TestBan/* (all subtests)

**Status**: Untested because faucetOffchain fails first. The ban/conviction system exists (`conviction_repo.rs`, `domain/conviction.rs`) but the enforcement during rounds (detecting missing nonces, invalid signatures, missing forfeits) may not work correctly.

**Complexity**: Unknown until root causes are fixed

---

## Test Dependency Tree

```
Root Cause #1 (empty witness) blocks:
  └── TestBatchSession/refresh_vtxos (partially works, fails on LockedAmount assertion)
  └── All boarding-based tests (TestReactToFraud/*, TestSweep/batch, etc.)

Root Cause #2 (no notes) blocks:
  └── faucetOffchain() → ALL tests except TestBatchSession/refresh_vtxos

Root Cause #3 (LockedAmount) blocks:
  └── TestBatchSession/refresh_vtxos final assertion
  └── TestFee final assertion
```

## Recommended Fix Order

1. **Fix #1**: Server wallet fee input signing → unlocks boarding-based settle
2. **Fix #3**: Mark boarding UTXOs consumed → TestBatchSession/refresh_vtxos passes
3. **Fix #2**: Implement NoteService → unlocks 90% of tests
4. **Fix #4**: Intent Fees API → TestFee passes
5. **Fix #5**: Admin Sweep → TestSweep/force_by_admin passes
6. **Fix #6**: Asset RPCs → TestAsset/* passes
7. Investigate & fix remaining issues (#8-#10) as they surface
