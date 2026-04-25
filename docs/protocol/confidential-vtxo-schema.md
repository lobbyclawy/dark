# Confidential VTXO protobuf schema (#531, #537)

This document describes the wire-protocol additions introduced for
Confidential VTXOs (CV-M2 + CV-M3 milestones). It is the authoritative
reference for the messages that live in `proto/ark/v1/confidential.proto`,
`proto/ark/v1/confidential_tx.proto`, and the extensions to `Vtxo` /
`IndexerVtxo` and `ArkService`.

## Goals

- Hide the amount and recipient of a VTXO behind a Pedersen commitment, a
  Bulletproofs range proof, and a stealth ephemeral pubkey.
- Stay strictly **additive** with respect to the existing transparent
  schema, so unmodified Go arkd clients (and the vendored E2E suite) keep
  interoperating with new servers.
- Reserve a clear field-number block for future confidential extensions so
  contributors can add typed metadata without rolling the whole schema.

## Field numbering

| Range     | Reserved for                                                  |
|-----------|---------------------------------------------------------------|
| 1 - 14    | Legacy transparent fields on `Vtxo` / `IndexerVtxo`. Frozen.  |
| 15 - 99   | Reserved for future *transparent* extensions.                 |
| 100 - 199 | Reserved for *confidential* extensions. The `vtxo_body` oneof lives at field 100 (transparent marker) and 101 (confidential payload). |

The `ConfidentialVtxo` message itself reserves its own 100-199 range for
future confidential-only fields (e.g. asset commitments).

## New messages

All messages live under package `ark.v1` and are imported via
`ark/v1/confidential.proto`.

### `PedersenCommitment`

Compressed elliptic-curve point committing to `vG + rH`. Wire:

```protobuf
message PedersenCommitment {
  bytes point = 1; // 33 bytes (SEC1 compressed)
}
```

Servers MUST reject commitments that are not 33 bytes long. The point is
produced by `dark-confidential::commitment` (see #525).

### `RangeProof`

Opaque Bulletproofs range-proof bytes:

```protobuf
message RangeProof {
  bytes proof = 1; // implementation-defined; variable length
}
```

Per #525 the proof byte layout is an implementation detail and MUST NOT be
parsed on the wire — verifiers pass the blob to
`dark-confidential::range_proof::verify`.

### `BalanceProof`

Schnorr-like balance proof asserting that input/output commitments sum to
zero:

```protobuf
message BalanceProof {
  bytes sig = 1; // 65 bytes: 33-byte R || 32-byte big-endian s
}
```

See #526 for the exact algorithm and DST tags.

### `Nullifier`

Deterministic 32-byte spend tag produced by
`dark-confidential::nullifier` (#527):

```protobuf
message Nullifier {
  bytes value = 1; // 32 bytes
}
```

Two confidential VTXOs that share a nullifier are double-spends.

### `EncryptedMemo`

Opaque ciphertext addressed to the recipient's ephemeral pubkey:

```protobuf
message EncryptedMemo {
  bytes ciphertext = 1; // implementation-defined
}
```

The decryption protocol is defined by the stealth scheme (#523/#524).

### `ConfidentialVtxo`

The composite confidential payload that replaces the cleartext
`amount`/`script` of a `Vtxo` when the `vtxo_body` oneof is set to
`confidential`:

```protobuf
message ConfidentialVtxo {
  PedersenCommitment amount_commitment = 1;
  RangeProof         range_proof       = 2;
  bytes              owner_pubkey      = 3; // 33 bytes
  bytes              ephemeral_pubkey  = 4; // 33 bytes
  EncryptedMemo      encrypted_memo    = 5;
  Nullifier          nullifier         = 6;
  reserved 100 to 199;                     // future confidential extensions
}
```

## Extensions to `Vtxo` / `IndexerVtxo`

Both message types gain a single oneof at field 100:

```protobuf
oneof vtxo_body {
  TransparentVtxoMarker transparent  = 100;
  ConfidentialVtxo      confidential = 101;
}
```

`TransparentVtxoMarker` is an empty message used purely as a sentinel —
transparent VTXOs continue to carry their full payload in the legacy
fields 1-14 directly on `Vtxo`/`IndexerVtxo`. Old clients that ignore the
oneof keep working unchanged.

When `confidential` is selected:

- `amount` MUST be zero.
- `script` MUST be empty.
- The real payload is the `ConfidentialVtxo` body.

## Backward / forward compatibility

| Scenario                                         | Outcome                                     |
|--------------------------------------------------|---------------------------------------------|
| Old client reads new transparent VTXO            | Works — only legacy fields are populated.   |
| Old client reads new confidential VTXO           | Sees `amount=0`, empty `script`, ignores unknown oneof. SHOULD treat as opaque. |
| New client reads old transparent VTXO            | Works — `vtxo_body` is `None`; legacy fields populated. |
| Old wire bytes round-trip through new schema     | Decode succeeds; `vtxo_body == None`. (Asserted by `dark-api::tests::test_transparent_vtxo_wire_compat`.) |

## Field additions: breaking vs. additive

- `confidential.proto` (new file): purely additive.
- `Vtxo.vtxo_body` (field 100/101): **additive**. A oneof at a previously-
  unused field number is a non-breaking change in proto3.
- `IndexerVtxo.vtxo_body` (field 100/101): **additive**, same reasoning.
- `Vtxo.reserved 15..=99` and `IndexerVtxo.reserved 15..=99`: declarative-
  only; reservations cannot be observed on the wire and are non-breaking.

No existing field numbers were renumbered, removed, or repurposed.

## Confidential transaction wire shape (#537)

CV-M3 adds the wire types for *submitting* a confidential off-chain
transaction. They live in `proto/ark/v1/confidential_tx.proto` and reuse
`Nullifier`, `PedersenCommitment`, `RangeProof`, `BalanceProof`, and
`EncryptedMemo` from `confidential.proto`.

### `ConfidentialTransaction`

```protobuf
message ConfidentialTransaction {
  repeated Nullifier              nullifiers     = 1;
  repeated ConfidentialVtxoOutput outputs        = 2;
  BalanceProof                    balance_proof  = 3;
  uint64                          fee_amount     = 4; // plaintext, ADR-0004
  uint32                          schema_version = 5; // starts at 1
  reserved 6 to 99;
  reserved 100 to 199;
}
```

`fee_amount` is **plaintext** per the in-flight ADR-0004 (#536, on
`feat/m3-dd-fee`). The trade-off is documented inline in the proto: a hidden
fee would force a second range proof on every submission for marginal
privacy benefit, since fee bands already leak through transaction size and
mempool timing. The proto comment will be updated to point at the final ADR
filename (`docs/adr/0004-confidential-tx-fee.md`) once #536 lands.

`schema_version` lets servers reject older or future wire shapes
deterministically (see `ERROR_SCHEMA_VERSION_MISMATCH` below). Starts at `1`
for this milestone.

### `ConfidentialVtxoOutput`

```protobuf
message ConfidentialVtxoOutput {
  PedersenCommitment commitment       = 1;
  RangeProof         range_proof      = 2;
  bytes              owner_pubkey     = 3; // 33 bytes
  bytes              ephemeral_pubkey = 4; // 33 bytes
  EncryptedMemo      encrypted_memo   = 5;
  reserved 6 to 99;
  reserved 100 to 199;
}
```

The shape mirrors `ConfidentialVtxo` minus the `nullifier` field —
nullifiers are derived deterministically from the resulting outpoint
server-side per #527, so transmitting one would be either redundant or a
forgery vector.

### Submission RPC: parallel method, not `oneof`

A new RPC `ArkService.SubmitConfidentialTransaction` is added next to the
existing `SubmitTx`:

```protobuf
rpc SubmitConfidentialTransaction(SubmitConfidentialTransactionRequest)
    returns (SubmitConfidentialTransactionResponse);
```

Issue #537 explicitly allowed either a `oneof` arm inside `SubmitTxRequest`
or a parallel method. We chose the parallel method because:

- The transparent `SubmitTx` wire shape stays bit-for-bit identical, so
  every existing transparent client (including the vendored Go arkd test
  suite) keeps working without recompilation.
- Operators get a clean rollout switch: enabling/disabling confidential
  submissions is a single boolean on the new RPC, not a code change in the
  shared transparent path.
- The two surfaces return materially different responses (txid vs.
  accept/reject + structured error enum), which would be awkward to express
  inside one RPC without forcing the response into a `oneof` as well.

### `SubmitConfidentialTransactionRequest` / `Response`

```protobuf
message SubmitConfidentialTransactionRequest {
  ConfidentialTransaction transaction = 1;
  reserved 2 to 99;
}

message SubmitConfidentialTransactionResponse {
  bool   accepted      = 1;
  Error  error         = 2;
  string error_message = 3;
  string ark_txid      = 4;
  reserved 5 to 99;

  enum Error {
    ERROR_UNSPECIFIED              = 0;
    ERROR_NULLIFIER_ALREADY_SPENT  = 1;
    ERROR_INVALID_RANGE_PROOF      = 2;
    ERROR_INVALID_BALANCE_PROOF    = 3;
    ERROR_FEE_TOO_LOW              = 4;
    ERROR_MALFORMED_OUTPUT         = 5;
    ERROR_SCHEMA_VERSION_MISMATCH  = 6;
  }
}
```

Adding a new error variant in the future MUST take a new enum tag; existing
tags MUST NOT be renumbered.

### Backward compatibility (CV-M3 additions)

| Scenario                                                         | Outcome                                  |
|------------------------------------------------------------------|------------------------------------------|
| Old transparent client calls `SubmitTx`                          | Unchanged. Wire bytes are identical.     |
| Old transparent client introspects the `ArkService` descriptor   | Sees a new RPC it does not call. Fine.   |
| New client calls `SubmitConfidentialTransaction` against an old server | Server returns `Unimplemented` (no handler exists pre-#542). |
| `ConfidentialTransaction` decoded under a future schema with new fields | Old code ignores unknown tags (proto3 default behaviour). |

### Handler & validation status

The current crate ships only the proto schema and the generated tonic/prost
bindings. The actual handler is tracked in #542 and the validation logic
lives in #538; until those land, calling
`SubmitConfidentialTransaction` returns `Status::unimplemented`.

## Validation

- `cargo build --workspace` succeeds; `tonic-build` regenerates the
  bindings cleanly.
- `cargo test -p dark-api --lib` passes, including the existing wire-compat
  tests `test_confidential_proto_types_exist` and
  `test_transparent_vtxo_wire_compat`, plus the new
  `test_confidential_tx_proto_types_exist`.
- `buf lint` (run from `proto/`) passes with the repo's standard ruleset.
- `cargo fmt --check` passes.
