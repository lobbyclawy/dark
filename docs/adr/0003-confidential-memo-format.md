# ADR-0003: Confidential VTXO memo format and encryption scheme

- **Status:** Proposed
- **Date:** 2026-04-24
- **Milestone:** CV-M2 (Confidential VTXO Types & Storage)
- **Drives:** #529 → unblocks #530, constrains #551, #554, #555, #558
- **Affects:** confidential VTXO bytes only; transparent paths untouched (#520 parity gate)

## Context

Every confidential output carries an `encrypted_memo` field that only the
recipient can decrypt. The memo carries the data the recipient needs to later
spend the VTXO — the plaintext amount, the Pedersen blinding factor, and a
binding tag for the one-time spend key — none of which the operator may see.
The operator must store and forward the memo as opaque ciphertext.

Issue #529 asks us to fix the wire layout, the key-agreement scheme, the KDF,
the AEAD, the plaintext schema, and the failure-mode analysis. The format must
be additive on the wire (new fields on the confidential `Vtxo` variant only —
see #530), versioned, and bound tightly enough that an operator cannot graft a
valid memo onto a different output, replay a stale memo, or substitute a
different version after the fact.

The memo design has a coordination point with the Milestone 5 stealth-address
work (#551 design, #553/#554 implementation): the ephemeral keypair the sender
generates per output is reused for both stealth one-time-key derivation and
memo ECDH. This ADR pins the minimum constraint that #551/#554 must respect so
the two schemes share keys coherently.

## Requirements

- Confidentiality of `(amount, blinding, one_time_spend_tag)` against everyone
  except the recipient who holds the scan secret.
- AEAD authenticity: any single-bit tamper of the memo bytes, the version, the
  ephemeral pubkey, the nonce, or the ciphertext must be detectable.
- Binding to the target VTXO: an operator must not be able to copy a valid
  memo from one VTXO and attach it to another. The owning one-time pubkey is
  cryptographically bound to the memo via AEAD associated data.
- Cross-version safety: a v1 memo cannot be re-tagged as some future v2 memo
  without breaking authenticity.
- Compact: the memo lives inside every confidential VTXO and travels through
  rounds; total size on the order of a hundred bytes.
- Reproducible: identical inputs (`ephemeral_sk`, `scan_pk`, `one_time_pk`,
  plaintext) produce bit-identical memo bytes — necessary for cross-language
  test vectors.
- Reuses curve material already in the workspace. No new curve assumptions
  beyond `secp256k1 = 0.29` (the workspace pin) and the audited primitives in
  `chacha20poly1305 = 0.10` / `hkdf = 0.12` / `sha2 = 0.10`.

## Decision

Adopt **v1 confidential memo format**:

- ECDH on `secp256k1` between sender's fresh per-output ephemeral keypair and
  the recipient's published scan pubkey.
- HKDF-SHA256 over the compressed shared point, derive a 32-byte AEAD key and
  a 12-byte nonce.
- ChaCha20-Poly1305 (RFC 8439) AEAD over a fixed-width 72-byte plaintext.
- Associated data binds the memo to the version byte, the ephemeral pubkey,
  and the recipient's one-time output pubkey.
- Single-byte version prefix; v1 = `0x01`.

### Wire layout (134 bytes)

| Field                  | Offset | Size  | Notes                                          |
|------------------------|--------|-------|------------------------------------------------|
| `version_byte`         | 0      | 1     | `0x01` for v1                                  |
| `ephemeral_pk`         | 1      | 33    | secp256k1 compressed                           |
| `nonce`                | 34     | 12    | HKDF-derived (see KDF)                         |
| `ciphertext`           | 46     | 72    | ChaCha20 keystream over the encoded plaintext  |
| `poly1305_tag`         | 118    | 16    | Poly1305 over (AAD, ciphertext)                |
| **total**              |        | **134** |                                              |

Bytes are concatenated in declaration order with no padding. Reserved version
bytes: `0x00` (never valid), `0xff` (reserved as escape for future schemes).

### Plaintext layout (72 bytes)

| Field                  | Offset | Size | Encoding         |
|------------------------|--------|------|------------------|
| `amount`               | 0      | 8    | `u64` little-endian |
| `blinding`             | 8      | 32   | secp256k1 scalar, big-endian (matches `secp256k1::SecretKey::secret_bytes`) |
| `one_time_spend_tag`   | 40     | 32   | opaque 32 bytes; defined by the spend-key derivation in #553/#554 |
| **total**              |        | **72** |                |

Fixed-width — there is no length prefix and no optional fields. A future
plaintext extension requires a new `version_byte`.

### Key agreement

```text
ephemeral_pk      = ephemeral_sk · G                      (sender, fresh per output)
shared_point      = ephemeral_sk · scan_pk                (sender)
                  = scan_sk · ephemeral_pk                (recipient)
shared_point_bytes = compressed_serialize(shared_point)   (33 bytes)
```

The full compressed point — both the y-parity prefix and the 32-byte
x-coordinate — feeds HKDF. Hashing the x-coordinate alone (the libsecp
default) would leak no security but loses one bit of entropy and diverges
from how the rest of `dark-confidential` already serialises curve points.

### KDF

```text
(aead_key || nonce) = HKDF-SHA256(
    salt = ephemeral_pk_bytes,           // 33 bytes (compressed)
    ikm  = shared_point_bytes,            // 33 bytes (compressed)
    info = "dark-confidential/memo/v1",   // 25 bytes ASCII
    L    = 44,                            // 32 + 12
)
aead_key = first 32 bytes of OKM
nonce    = next 12 bytes of OKM
```

Including `ephemeral_pk` as the salt binds the KDF output to the specific
ephemeral keypair. `info` carries the version: bumping to `…/v2` produces
disjoint keys even if the rest of the inputs match.

### AEAD

ChaCha20-Poly1305 (RFC 8439). Input/output as in libsodium's
`crypto_aead_chacha20poly1305_ietf_*` and the `chacha20poly1305 = 0.10` Rust
crate.

```text
aad = version_byte || ephemeral_pk || one_time_pk        (1 + 33 + 33 = 67 bytes)
(ciphertext, poly1305_tag) = ChaCha20-Poly1305-Encrypt(
    key       = aead_key,
    nonce     = nonce,
    plaintext = encoded_plaintext_72,
    aad       = aad,
)
```

`one_time_pk` is the spend-locking pubkey on the target VTXO — i.e. the
output of the stealth one-time-key derivation in #554 — encoded as a 33-byte
compressed point. It is not on the wire of the memo itself; the recipient
recovers it from the same VTXO record that carries the memo. Including it in
AAD ties the memo to that specific output: an operator cannot move a
correctly-encrypted memo to a different VTXO without invalidating the tag.

## Why ChaCha20-Poly1305 (not AES-256-GCM)

Both AEADs satisfy the issue's requirements. The ADR locks ChaCha20-Poly1305
for v1 because:

- **Software constant-time on every target.** The release matrix in
  `release.yml` includes `aarch64-unknown-linux-gnu` and
  `aarch64-apple-darwin`. ChaCha20-Poly1305 has uniform constant-time
  performance without AES-NI/ARMv8-Crypto extensions. AES-GCM does not.
- **Nonce-misuse footgun.** AES-GCM catastrophically fails (key recovery)
  under nonce reuse. ChaCha20-Poly1305 is also unsafe under nonce reuse but
  fails as plaintext disclosure rather than key disclosure — strictly better
  failure mode in case a future implementation regresses key-derivation
  freshness. v1's deterministic HKDF-derived nonce is structurally safe (see
  failure-mode analysis), but defence-in-depth still favours ChaCha.
- **Smaller audit surface.** `chacha20poly1305 = 0.10` is RustCrypto's
  audited reference; the equivalent AES-GCM stack pulls in `aes-gcm`,
  `ghash`, and platform-specific intrinsics.
- **Ecosystem.** Bitcoin-adjacent stacks (Lightning's BOLT-08 transport,
  Tor v3 onion services, Wireguard, libsodium sealed boxes) already use
  ChaCha20-Poly1305. Wallet developers porting to other languages will find
  parity libraries everywhere.

AES-GCM is **not** an acceptable substitute for v1. A future v2 may revisit
the choice if hardware-AEAD throughput becomes a bottleneck on operator
hardware.

## Why HKDF-SHA256

- Standardised (RFC 5869), portable, available in every target language.
- Aligns with ADR-0002 which already uses SHA-256 family for nullifier
  derivation; one hash family across the crate.
- Domain-separated `info` parameter lets us share the salt format across
  future memo versions without key collisions.

A simpler `SHA-256(salt || ikm || info)` would be functionally adequate but
HKDF's extract-then-expand structure is the standard idiom for ECDH-derived
key material; deviating buys nothing.

## Why deterministic HKDF-derived nonce

The nonce is bound to the same inputs as the AEAD key. Each VTXO uses a
fresh `ephemeral_sk`, so the HKDF salt+ikm tuple is unique per output, and
the (key, nonce) pair therefore never repeats in honest use. Putting the
nonce on the wire (rather than re-deriving on receipt) is intentional:

- Lets the recipient detect a malformed memo without doing the (expensive)
  ECDH first — parse, then derive, then verify.
- Reserves wire space for a future v2 that may use a randomly-sampled nonce
  (e.g. if the spec moves to non-deterministic memos for resistance against
  ephemeral-key fingerprinting).

The recipient does not need to verify `wire_nonce == hkdf_nonce`: Poly1305
already binds the tag to the wire nonce, so any tamper invalidates the tag.

## Failure-mode analysis

### Memo malleation (single-bit flip anywhere on the wire)

Every byte of the wire is covered:
- `version_byte` is in AAD → tag fails.
- `ephemeral_pk` is in AAD and is the HKDF salt → tag fails (and the
  recipient's recomputed key differs from what the sender used).
- `nonce` is the AEAD nonce → tag fails.
- `ciphertext` is covered by Poly1305 → tag fails.
- `poly1305_tag` is the tag itself → fails.

Negative scenario G in the test vectors confirms: flipping the last byte of
the wire (inside the Poly1305 tag) produces `aead tag` failure on decrypt.

### Replay / cross-output graft

An operator who has a valid memo for VTXO `X` (one-time pubkey `P_X`) cannot
attach it to a different VTXO `Y` (one-time pubkey `P_Y ≠ P_X`). The
recipient's AAD is computed from the VTXO they are decrypting against; if
they decrypt the memo expecting `P_Y`, the AAD is `version || ephemeral_pk
|| P_Y`, which differs from the AAD the sender used (`… || P_X`), and the
tag fails. Negative scenario E confirms.

A *verbatim* replay (memo bytes attached unchanged to VTXO `X` again) is not
prevented at the memo layer — by construction it is the same valid memo for
the same VTXO, indistinguishable from the original. Replay defence at the
VTXO layer is the nullifier mechanism (ADR-0002), not memo authenticity.

### Wrong-recipient decryption

A wallet that does not hold the matching `scan_sk` derives a different
shared point, hence a different HKDF output, hence a different AEAD key.
Decryption fails on the tag and the wallet learns nothing about the
plaintext. Negative scenario D confirms.

### Operator forgery

The operator does not hold any wallet's `scan_sk`, so it cannot derive any
recipient's AEAD key. Forging a memo whose tag verifies under a chosen AAD
is equivalent to ChaCha20-Poly1305 forgery, which is infeasible under
standard assumptions. The operator can of course **omit** the memo or
**replace** it with a random blob, but in both cases the recipient's
decryption fails and the recipient knows the VTXO is unspendable for them.
This is detectable; recovering the lost amount is the recipient-scanning
problem (#558), not a memo-format problem.

### Cross-version downgrade

The version byte is the first byte of AAD. An attacker cannot strip a v2
memo and present it as v1 (or vice versa) without breaking the tag.
Negative scenario F confirms (version mutated to `0x02` is rejected by the
parser; even if a hypothetical parser accepted it, AAD divergence would
trip the tag).

### Ephemeral key reuse by a buggy sender

If a sender wallet bug reuses `ephemeral_sk` across two memos to the same
recipient, the (key, nonce) pair from HKDF repeats, and ChaCha20-Poly1305
nonce-reuse leaks the XOR of the two plaintexts. The mitigation is policy,
not protocol: implementers MUST sample `ephemeral_sk` from a CSPRNG fresh
per output and MUST NOT cache or re-use it. This requirement propagates as
a constraint on #553/#554 and on every wallet implementation. A future v2
may add a per-message random salt to HKDF to make this footgun structurally
impossible at the cost of 16 wire bytes; deferred.

### Length / structure attacks

The plaintext is fixed at 72 bytes; the wire is fixed at 134 bytes.
Anything else is rejected on parse before any cryptographic work runs. The
parser must check length before touching ECDH or HKDF.

## Test vectors

Three positive vectors (A/B/C) and four negative scenarios (D/E/F/G) are
materialised byte-exactly in
[`docs/adr/vectors/0003-memo-vectors.json`](vectors/0003-memo-vectors.json),
generated by `contrib/memo-vector-gen/`. The generator is reproducible: same
input scalars + same crate versions ⇒ identical outputs.

Implementation issues MUST embed all three positive vectors as test fixtures
and assert byte-equality of the memo wire. The negative scenarios MUST be
asserted as decryption failures.

### Vector A — canonical happy-path

| Field                  | Value (hex)                                                          |
|------------------------|----------------------------------------------------------------------|
| `ephemeral_sk`         | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`   |
| `scan_sk`              | `1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100`   |
| `one_time_sk` *(for derivation only)* | `2020202020202020202020202020202020202020202020202020202020202020`   |
| `amount`               | `21000000` (decimal) → `406f400100000000` (LE)                       |
| `blinding`             | `1111…11` (32 × `0x11`)                                              |
| `one_time_spend_tag`   | `2222…22` (32 × `0x22`)                                              |
| → `ephemeral_pk`       | `036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2` |
| → `scan_pk`            | `025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486` |
| → `one_time_pk`        | `03187db77a59f1c5f3cfd2296f87ebd7e829226b0f628d9efe4b9f221414e3b967` |
| → `shared_point`       | `03089a68a169fc50f5ef189cc9962fc0f2d7a61fdb4ecdbf417f70b1a1f5b374f5` |
| → `aead_key`           | `d654973d8ae1a2c6a641d55eccdcbe9be0735d0f20ba89bb677b16b1d0a10f17`   |
| → `nonce`              | `863137b3b4329ab0b9b1ef00`                                           |
| → `aad` (67 B)         | `01` ‖ `ephemeral_pk` ‖ `one_time_pk`                                |
| → **`memo_wire`** (134 B) | `01036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2863137b3b4329ab0b9b1ef00019ded27e89f4a3d7f64d0a7e56ba0ea827f15a2ec8091bdfe9159de52f47bf8ff3a936bdacca386464fe70f439c130b4606be924c60126eb8d1a9d264c6ebc5cc28362649a5153b0291d04ea09b69cf95f2b8b1a86d1a57` |

### Vector B — zero amount, zero blinding

| Field                  | Value (hex)                                                          |
|------------------------|----------------------------------------------------------------------|
| `ephemeral_sk`         | `aaaa…aa` (32 × `0xaa`)                                              |
| `scan_sk`              | `bbbb…bb` (32 × `0xbb`)                                              |
| `one_time_sk`          | `cccc…cc` (32 × `0xcc`)                                              |
| `amount`               | `0`                                                                  |
| `blinding`             | `0000…00`                                                            |
| `one_time_spend_tag`   | `3333…33`                                                            |
| → `ephemeral_pk`       | `026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3` |
| → `scan_pk`            | `0268680737c76dabb801cb2204f57dbe4e4579e4f710cd67dc1b4227592c81e9b5` |
| → `one_time_pk`        | `02b95c249d84f417e3e395a127425428b540671cc15881eb828c17b722a53fc599` |
| → **`memo_wire`** (134 B) | `01026a04ab98d9e4774ad806e302dddeb63bea16b5cb5f223ee77478e861bb583eb3189f4064c7a97bffa93d052cc8075d23370c23e51e178256b748f4f43913a92af2f1a1fe8b4fe58aeaf0ac1e72800f0b08125bbe5711b8c9ab8897175254a6acdde7210932802bc9e5e2b49218963f8a51159fa661cb2ec9d3cdc525dfbbb58c4f8f288d` |

### Vector C — `u64::MAX` amount, all-`0xff` blinding (small-scalar inputs)

This vector uses `ephemeral_sk = 1` and `scan_sk = 2` so the resulting
ephemeral_pk equals the curve generator `G`. It is a minimal-input test for
verifying byte-exact computation across implementations and is not
representative of real-world memo construction (a real sender MUST sample
`ephemeral_sk` from a CSPRNG; see failure-mode analysis).

| Field                  | Value (hex)                                                          |
|------------------------|----------------------------------------------------------------------|
| `ephemeral_sk`         | `0000…0001`                                                          |
| `scan_sk`              | `0000…0002`                                                          |
| `one_time_sk`          | `0000…0003`                                                          |
| `amount`               | `18446744073709551615` (`u64::MAX`) → `ffffffffffffffff` (LE)        |
| `blinding`             | `ffff…ff`                                                            |
| `one_time_spend_tag`   | `4444…44`                                                            |
| → `ephemeral_pk`       | `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798` (= `G`) |
| → `scan_pk`            | `02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5` |
| → `one_time_pk`        | `02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9` |
| → **`memo_wire`** (134 B) | `010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798973e4e8fb4f4b299cc16c1434f0279c8ff26087f0227ff8fd84426a8cbdbcff47e64443b707161628a36c64a869816669ad55f712e3f65746284800106a12dd107d8904b20cb92acd82181bce2a0aad858de74c2309a1823771ca0b20986d6270fb355e9` |

### Negative scenarios (built from Vector A)

| ID | Mutation                                                | Expected outcome                                          |
|----|---------------------------------------------------------|-----------------------------------------------------------|
| D  | Decrypt with a different `scan_sk` (`0000…0099`)        | AEAD tag verification fails                               |
| E  | Recipient supplies `one_time_pk` with byte 1 XOR `0x01` | AEAD tag verification fails (AAD divergence)              |
| F  | Wire byte 0 mutated from `0x01` to `0x02`               | Parser rejects on unknown version                         |
| G  | Wire last byte (Poly1305 tag) flipped                   | AEAD tag verification fails                               |

## Consequences

### Positive

- One self-contained ADR pins every byte of the memo. Implementations in
  any language can compile and verify against the same vectors.
- Reuses curve material the workspace already pins (`secp256k1 = 0.29`).
  No new curve assumption.
- AAD binding to `one_time_pk` makes operator-side memo grafting
  cryptographically detectable, not merely policy-prohibited.
- Versioning lives in one byte that is also part of AAD, so future formats
  cannot be downgraded onto v1.

### Negative / follow-ups

- **134 bytes per memo.** A 500-output round therefore carries ~65 KB of
  memo bytes in addition to the range proofs. This is acceptable at launch
  given the existing range-proof bandwidth from ADR-0001.
- **Deterministic HKDF nonce relies on per-output ephemeral freshness.**
  Implementations MUST enforce CSPRNG sampling of `ephemeral_sk`. A
  follow-up issue **[FU-MEMO-V2]** is appropriate if we ever need a random
  salt in HKDF as a defence-in-depth measure.
- **No forward secrecy.** A recipient who later loses `scan_sk` can be
  retroactively decrypted by anyone who recorded their memos. Forward
  secrecy on a per-memo basis would require an interactive handshake the
  operator cannot mediate; out of scope.
- **No padding / length hiding.** The plaintext is fixed-width by design,
  so there is nothing to pad. If a future plaintext has variable-length
  fields, the new version must specify a padding scheme.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's soundness.
Any deviation must reopen ADR-0003 before landing.

- **#530 (`Vtxo` enum extension)** MUST place `encrypted_memo` and
  `ephemeral_pubkey` on the `Confidential` variant only. The wire format
  for the memo is exactly the 134-byte blob defined here, opaque to
  `dark-core`.
- **#531 (proto schema)** MUST encode the memo as a single `bytes` field
  carrying the 134-byte wire. The version byte is part of the wire, not a
  separate proto field — keeping versioning a memo-internal concern.
- **#551 ([Design] stealth address derivation)** MUST specify the scan
  keypair as a `secp256k1` keypair using compressed pubkey encoding, so
  the ECDH in this ADR is well-defined. Any deviation (e.g. using a
  different curve for scan keys) reopens this ADR.
- **#553 (dual-key meta-address)** MUST publish `scan_pk` as a 33-byte
  compressed point. The bytes of `scan_pk` consumed by ECDH are exactly
  those bytes, with no additional encoding.
- **#554 (sender-side one-time key derivation)** MUST reuse the same
  `ephemeral_sk` for: (a) deriving the one-time output pubkey
  (`one_time_pk = spend_pk + H(ECDH(ephemeral_sk, scan_pk)) · G`), and
  (b) deriving the memo AEAD key as defined in this ADR. The
  `ephemeral_pk` field on the VTXO is single-sourced and serves both
  stealth detection and memo decryption. A separate ephemeral keypair
  per concern would double wallet scan cost and break the canonicalised
  wire layout.
- **#555 (recipient-side stealth scanning)** MUST decrypt the memo using
  the procedure in this ADR, not a recipient-defined alternative. The
  recipient derives `aead_key` via HKDF on `(ephemeral_pk, ECDH(scan_sk,
  ephemeral_pk))`, then ChaCha20-Poly1305-decrypts with AAD =
  `version || ephemeral_pk || one_time_pk`. `one_time_pk` for AAD comes
  from the same VTXO record being decrypted.
- **Implementations of memo `encrypt` / `decrypt`** MUST reject any wire
  whose length is not 134 bytes before touching ECDH or HKDF, and MUST
  reject any version byte other than `0x01` (or future-pinned values)
  before touching the AEAD.

## References

- Issue #529 (this ADR)
- Issue #530 — `Vtxo` enum extension (consumes this format)
- Issue #531 — proto schema for confidential VTXOs
- Issue #551 — stealth address derivation paths (cross-constraint)
- Issue #553 — dual-key meta-address
- Issue #554 — sender-side one-time key derivation
- Issue #555 — recipient stealth scanning
- ADR-0001 — secp256k1-zkp integration strategy
- ADR-0002 — nullifier derivation scheme and domain separation
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- `chacha20poly1305 = 0.10`: <https://crates.io/crates/chacha20poly1305/0.10.1>
- `hkdf = 0.12`: <https://crates.io/crates/hkdf/0.12.4>
- Test vectors: [`docs/adr/vectors/0003-memo-vectors.json`](vectors/0003-memo-vectors.json)
- Vector generator: [`contrib/memo-vector-gen/`](../../contrib/memo-vector-gen/)
