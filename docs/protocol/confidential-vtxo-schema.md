# Confidential VTXO protobuf schema (#531)

This document describes the wire-protocol additions introduced for
Confidential VTXOs (CV-M2 milestone). It is the authoritative reference for
the messages that live in `proto/ark/v1/confidential.proto` and the
extensions to `Vtxo` / `IndexerVtxo`.

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

## Validation

- `cargo build --workspace` succeeds; `tonic-build` regenerates the
  bindings cleanly.
- `cargo test -p dark-api --lib` passes, including the new wire-compat
  tests `test_confidential_proto_types_exist` and
  `test_transparent_vtxo_wire_compat`.
- `buf lint` (run from `proto/`) passes with the repo's standard ruleset.
- `cargo fmt --check` passes.
