# ADR-M6-DD: Compliance proof bundle wire format

- **Status:** Proposed
- **Date:** 2026-04-25
- **Milestone:** CV-M6 (Selective Disclosure & Compliance)
- **Drives:** #562 → unblocks #564, #565 → constrains #566, #567, #568, #569
- **Affects:** the wire artefact a wallet hands to an auditor / regulator /
  exchange counterparty; no on-chain changes; no consensus-relevant
  changes; transparent VTXO paths untouched (#520 parity gate).
- **Companion ADRs:** ADR-0003 (memo format — defines the
  `(amount, blinding, one_time_spend_tag)` triple the `VtxoReveal` proof
  opens), ADR-M5-DD-stealth-derivation (defines the `MetaAddress` and
  the per-output ephemeral-pubkey that scope-binding hashes pin), ADR
  M5-DD-announcement-pruning (defines the round/announcement identifiers
  the bundle's scope hash references).

## Context

A **compliance proof bundle** is the standalone artefact a confidential
VTXO wallet hands to a third party — an auditor performing a periodic
attestation, a regulator running a Travel-Rule check, an exchange's
deposit-screening pipeline, or a counterparty asking for a one-shot
"prove this VTXO is real" before accepting an off-protocol payment.

The bundle MUST be verifiable **without access to the operator** beyond
the public on-chain round commitments and the public announcement
indexes — the auditor pulls those from any honest mirror (or runs their
own light client) and feeds the bundle to a verifier that produces a
single `Result<(), VerificationError>`. The operator is not in the
trust path of verification; the operator's only role at compliance time
is the optional convenience endpoint `VerifyComplianceProof` (#569),
which is itself just a stateless verifier the operator runs against the
exact same public data the auditor would otherwise consult.

A bundle carries **zero or more** typed proof entries, each of which
makes one well-scoped statement about one VTXO (or a small graph of
VTXOs). The launch-scope proof types — pinned by the companion ADR
`m6-dd-launch-scope` (#563) — are:

- **`VtxoReveal`** — opens `(amount, blinding)` for one specific VTXO so
  the verifier can recompute `commit(amount, blinding)` and match it
  against the on-chain `amount_commitment`. MVP. (#565)
- **`ViewingKeyIssuance`** — issues a scoped, read-only key that lets
  the holder trial-decrypt every VTXO's memo within a declared scope
  (round range, account, or counterparty). MVP. (#564)
- **`BoundedRange`** — proves `committed_amount < threshold` (or
  `min ≤ amount ≤ max`) without revealing the amount; built on
  Bulletproofs with a tighter bound. Stretch. (#566)
- **`SourceOfFunds`** — proves "this VTXO traces back N ≤ max_depth
  hops to the disclosed ancestor VTXO" by walking the public
  commitment-path graph and signing the chain. Stretch. (#567)

The bundle's job is to be the **wire envelope** for any number of
these proof entries, plus the metadata an auditor needs to interpret
them: which VTXO each entry refers to, who issued the bundle, when,
under what scope, and (optionally) whom the bundle is addressed to.

The format decisions in this ADR are surprisingly load-bearing because
the bundle is the **only artefact** that crosses an organisational
trust boundary — wallet → auditor — without an interactive protocol on
either side. Every property the auditor relies on (scope binding,
issuer attribution, version negotiation, unknown-proof rejection) has
to be encoded as bytes that any third-party verifier with no shared
state with the wallet can re-derive from the bundle alone. The
constraints split into four families:

1. **Verifier-implementation difficulty.** Any third party — an
   auditing tool written in Go, a regulator's Python script, a
   browser-based explorer in TypeScript — must be able to parse,
   canonicalise and verify a bundle. The format choice is therefore
   biased toward "schemas that already have multi-language tooling"
   over "schemas that look elegant in Rust".
2. **Version evolution.** New proof types ship over time
   (`SourceOfFunds` after MVP, future zero-knowledge types under
   M7+). Old verifiers MUST safely reject unknown proof types
   *without crashing* and MUST surface a typed
   "unknown-proof-type" error. New verifiers MUST be able to verify
   old (subset) bundles without a code-path rewrite.
3. **Signature surface.** A bundle is signed (at minimum) by the
   wallet over the bundle contents so the auditor can attribute
   the disclosure. Optionally, the bundle is *also* signed by an
   auditor-binding key so the wallet pins which auditor the bundle
   was prepared for (rebinding-attack defence). The signed message
   MUST be byte-deterministic across implementations.
4. **Opaque-byte handling for proof blobs.** Several proof types
   (`BoundedRange`'s Bulletproofs blob; future zero-knowledge proofs)
   carry implementation-defined byte payloads that the *bundle*
   parser MUST NOT attempt to interpret. The bundle format must
   carry such payloads as length-prefixed opaque bytes; only the
   proof-type-specific verifier is allowed to look inside.

### Threat model

The compliance bundle exists to support **selective disclosure**. The
wallet is the trust root — it chooses what to put in the bundle and
what to leave out. The auditor / regulator / counterparty must learn
**only** what the bundle contents directly reveal, and nothing more:

- **Auditor-only revelation.** A bundle disclosing `VtxoReveal` for
  `vtxo_A` MUST NOT enable the verifier to learn anything about
  `vtxo_B` that is not also a target of an entry in the same bundle.
  Per ADR-0002 (nullifier derivation) and ADR-M5-DD-stealth-derivation,
  VTXOs from the same wallet are *unlinkable* from public data alone;
  the bundle MUST NOT bridge that unlinkability by accident (e.g. by
  embedding a wallet-wide pubkey that lets the auditor index every
  past VTXO the wallet ever held).
- **Issuer attribution, not identity.** The wallet signs the bundle
  with a per-bundle signing key (an x-only Schnorr key derived under
  ADR-M5-DD-stealth-derivation's path layout — see "Decision"
  below) so the verifier can attribute the bundle to a stable,
  pseudonymous issuer pubkey. The verifier learns *that bundle came
  from the same issuer as that other bundle* iff the wallet reuses
  the same issuer pubkey across both. The wallet decides per-issuance
  whether to reuse or rotate.
- **Auditor binding.** The bundle MAY pin a specific
  `auditor_pubkey` — the auditor's long-lived verification key — so
  a corrupt auditor cannot replay the bundle to a third party who
  trusts the same wallet but a different auditor. The wallet signs
  over the auditor pubkey as part of the canonical message; a
  different auditor cannot forge a re-binding.
- **No operator privilege.** The operator can verify the bundle (via
  #569) but learns no more than any other verifier — the bundle is
  publicly verifiable against public data, and #569 is a stateless
  service that does the math on a copy the auditor sent. The operator
  does NOT learn *who* the auditor is unless the bundle carries an
  auditor pubkey *and* the auditor is the one that submitted the
  bundle to the operator's RPC.
- **Forward-compat denial.** A bundle issued at v1 and replayed by a
  malicious party against a v2 verifier MUST be processed under v1
  semantics (the verifier honours the bundle's declared version).
  A bundle issued at v2 and replayed against a v1 verifier MUST be
  rejected with a typed `UnsupportedVersion` error — never silently
  partially-verified, and never crashed.
- **Unknown-proof-type denial.** A bundle that carries one
  `VtxoReveal` and one `FuturisticProofType_X` against a verifier
  that supports only `VtxoReveal` MUST verify the `VtxoReveal`
  entry and surface the unknown entry as `Skipped { reason:
  UnknownProofType { tag: 17 } }` in the verification result —
  never crash, never silently treat the bundle as fully valid.

### What the bundle is NOT

- **Not a wallet-to-wallet payment authorisation.** Confidential
  VTXOs are spent via the standard signing path; bundles never
  authorise a spend.
- **Not a session token.** A bundle is a one-shot artefact. Auditor
  sessions, if any, are layered on top by the auditor's own
  infrastructure (e.g. their CRM stamps the bundle hash into a
  case file).
- **Not encrypted at rest.** The bundle is plaintext on the wire
  and the auditor stores it in the clear (subject to their own
  data-handling rules). The wallet decides what to disclose; once
  disclosed, the auditor handles confidentiality on their side.
- **Not a privacy-preserving primitive on its own.** Bundles
  *carry* privacy-preserving proofs but are themselves a transparent
  envelope. The privacy properties are owned by the proof types
  inside the bundle, not by the envelope.

### What this ADR pins versus what other ADRs pin

| Decision | Owner |
|---|---|
| Wire-format choice (CBOR / protobuf / JSON+canonical) | **This ADR** |
| `BundleHeader` fields and ordering | **This ADR** |
| Proof-type tag registry (numeric IDs) | **This ADR** |
| Canonical signing-message construction | **This ADR** |
| Versioning rules (v1 vs v2 cross-compatibility) | **This ADR** |
| Issuer key derivation path | ADR-M5-DD-stealth-derivation (referenced) |
| `VtxoReveal` payload layout (`amount`, `blinding`, …) | #565 (consumes this ADR) |
| `ViewingKeyIssuance` scope semantics | `m6-dd-viewing-scope` (separate ADR) / #564 |
| `BoundedRange` payload (Bulletproofs blob layout) | #566 |
| `SourceOfFunds` payload (commitment-path layout) | #567 / `crates/dark-core/src/compliance.rs` |
| RPC contract for `VerifyComplianceProof` | #569 |
| CLI surface | #568 |

## Requirements

- **Standalone verifiability.** A bundle MUST be parseable and
  cryptographically verifiable using ONLY (a) the bundle bytes,
  (b) the public on-chain round commitments and announcement index
  for the round-range covered by the bundle, and (c) the auditor's
  own clock (for any expiry checks). NO operator query is required
  on the verification path.
- **Multi-language verifier support.** The format MUST be readable
  by at least one widely-used parser in Go, Python, TypeScript and
  Rust without a custom-written deserialiser. (Verifier
  implementations may still ship custom code for the
  proof-type-specific verifier; the *envelope* parser must be
  off-the-shelf.)
- **Canonical (deterministic) encoding.** The bundle bytes that
  the issuer signs MUST be byte-identical when re-encoded by any
  conforming verifier. There is exactly one valid serialisation
  of a given bundle structure.
- **Signature attaches to canonical bytes.** The
  `issuer_signature` field signs a canonical pre-image derived
  from every other field in the bundle. Reordering, re-encoding,
  or partially decoding the bundle MUST invalidate the signature.
- **Version-tagged.** The first field of the wire encoding MUST
  be a version byte/integer. Verifiers MUST reject any bundle
  whose declared version is greater than the verifier's supported
  maximum. Bundles below the verifier's minimum supported version
  MUST also be rejected with a typed error.
- **Forward-compatible proof-type registry.** Each proof entry
  carries a numeric `proof_type_tag` from a registry pinned in
  this ADR. Verifiers MUST gracefully skip entries whose tag is
  unknown to them (surfacing `Skipped { reason: UnknownProofType }`
  per entry) without aborting verification of the bundle as a
  whole, EXCEPT when the bundle's `requires_all_known_types` flag
  is set (see "Decision" below).
- **Opaque payload preservation.** Each proof entry's payload bytes
  are an opaque length-prefixed blob from the envelope's perspective.
  The envelope parser MUST NOT attempt to validate the payload's
  internal structure. A future proof-type tag's payload may be a
  Bulletproofs blob, a SNARK proof, or a JSON document — the
  envelope is agnostic.
- **Bounded size.** The total bundle size MUST be bounded by a
  configurable verifier limit (default `MAX_BUNDLE_BYTES = 1 MiB`,
  see "Decision"). Each proof entry's payload MUST be bounded by a
  separate limit (default `MAX_ENTRY_BYTES = 256 KiB`). Verifiers
  MUST reject oversized bundles before parsing further.
- **Scope-bound.** The header carries a `scope_binding_hash` that
  pins the bundle to a declared scope (round range, VTXO set, time
  window, account). The signature covers this hash; replaying a
  bundle outside its declared scope is detectable.
- **Optional auditor binding.** The header MAY carry an
  `auditor_binding` field that names the intended auditor by
  pubkey. The signature covers this field; a missing field is
  encoded as the explicit "absent" tag, NOT as a zero-pubkey
  (which would be ambiguous).
- **Issuer attribution.** Every bundle MUST be signed by the
  issuer over the canonical message. The signature scheme is
  BIP-340 Schnorr over secp256k1, matching the rest of the
  workspace and reusing the existing `secp256k1 = 0.29` pin.
- **Replay defence.** The header carries an `issuance_timestamp`
  (UNIX seconds, signed) and a 32-byte fresh `nonce`. Both are
  signed. A verifier MAY reject bundles older than a
  verifier-configurable freshness window (default disabled — the
  freshness check is the auditor's policy, not a protocol
  requirement).
- **Compliance with `#![forbid(unsafe_code)]`.** The Rust
  reference parser ships in `dark-confidential::disclosure` and
  MUST compile under the workspace's `forbid(unsafe_code)`
  policy.
- **No new curve assumption.** Issuer signatures use secp256k1.
  No ed25519, no Ristretto.
- **Test-vector parity.** Every proof type's bundle encoding
  MUST have at least one byte-exact test vector (placeholder
  vectors at this ADR's land time; populated as #565/#564/#566/#567
  land their proof-type implementations).

## Options Considered

The format decision splits along three axes that are not strictly
independent:

- **Wire encoding** — CBOR (RFC 8949) with deterministic encoding,
  protobuf (google.protobuf v3), or JSON with a documented
  canonicalisation (RFC 8785 JCS or a custom rule). Each has
  different tooling, signature-stability and opaque-byte
  characteristics.
- **Schema-evolution strategy** — closed (every proof type is a
  named field of a fixed message; new types require a schema bump)
  vs. open (the proof-type tag is a numeric ID and the payload is
  opaque bytes; new types are additive and old verifiers skip
  unknown tags).
- **Signature-message construction** — sign the wire bytes
  directly (requires perfectly canonical encoding) vs. sign a
  derived hash over a structured pre-image (decouples signing
  from wire serialisation).

The three concrete options below each pick one combination. The
rejected combinations (e.g. JSON with a closed schema) are subsumed
into the discussion of their nearest neighbour.

### Option 1 — CBOR (RFC 8949) with deterministic encoding, open proof-type tag registry, signed pre-image is canonical CBOR bytes

The bundle is encoded as deterministic CBOR per RFC 8949 §4.2.1
("Core Deterministic Encoding"). Each proof entry is a CBOR map
with a numeric `proof_type_tag` and a CBOR `bytes`-typed payload.
Unknown tags are decodable as bytes by any conforming CBOR parser
without a schema. The signed message is `SHA256(canonical_cbor_bytes_of_signed_subset)`.

- **Verifier-implementation difficulty: low.** CBOR parsers ship
  in the standard library or first-party bindings for every
  language we care about (Rust: `ciborium = 0.2` or `serde_cbor`
  legacy; Go: `github.com/fxamacker/cbor/v2`; Python: `cbor2`;
  TypeScript: `cbor` / `cbor-x`). All four support deterministic
  encoding flag. No custom parser required.
- **Version evolution: excellent.** The proof-type tag is a CBOR
  unsigned-integer key inside an entry map. Adding a new tag is
  a registry update only; old verifiers parse the entry as
  `{tag: u64, payload: bytes}` and skip it on unknown tag with no
  schema change. CBOR's tag space is unbounded so the registry
  has no near-term ceiling.
- **Signature surface: small and clean.** The signed message is
  `SHA256(canonical_cbor(<header + signed_entries>))`. Every
  conforming CBOR encoder produces the same bytes for the same
  structured input under the deterministic profile (sorted map
  keys, shortest-form integers, definite-length strings). The
  signing pre-image is reproducible across languages.
- **Opaque-byte handling: native.** CBOR has a first-class `bytes`
  major type (major 2). A proof-type payload that is "an
  opaque Bulletproofs blob" is exactly a CBOR `bytes(...)` element
  in the entry map. The envelope parser does not need to know the
  inner structure to round-trip the bytes.
- **Schema-evolution mode: open.** Tags are numbers, not field
  names. Old verifiers see new tags as "unknown numeric key" and
  surface `Skipped { reason: UnknownProofType { tag: 17 } }`
  per entry without aborting.
- **Bundle size: compact.** CBOR's binary encoding is roughly
  1.3–1.5× the size of the raw payloads (overhead is the map
  framing per entry). For a 4-entry bundle with one Bulletproofs
  payload (~700 B), the envelope overhead is ~120 B.
- **Tooling friction: ~zero.** All four target languages have a
  one-line decode call. The deterministic-encoding flag is a
  per-encoder option, not a custom serialisation rule we have to
  enforce by hand.
- **Footgun: deterministic-encoding compliance.** Some CBOR
  encoders default to "valid CBOR" rather than "deterministic
  CBOR" (e.g. they may use indefinite-length strings or unsorted
  map keys). The reference parser MUST set the deterministic
  flag and MUST re-encode any decoded bundle through the same
  flag before signature verification — otherwise a bundle that
  *parses* as well-formed may produce a different pre-image when
  re-encoded by a non-conforming counterparty. Mitigation:
  document the deterministic-encoding contract in the ADR and
  add a signature-verification step that re-canonicalises the
  signed subset before checking the signature.
- **Cross-cutting risk: low.** The `dark-confidential` crate
  already uses `ciborium` for memo serialisation (ADR-0003); reusing
  the same dep keeps the workspace dep-graph stable and avoids
  pulling in a second serialisation framework.

### Option 2 — protobuf v3 with a closed-but-extensible schema, signed pre-image is `protowire.MarshalDeterministic`

The bundle is a `ComplianceProofBundle` protobuf message, with a
`oneof` over each known proof-type and `bytes unknown_payload` for
forward-compat. The signed message is the SHA-256 of the
canonical wire bytes produced by Go's `protowire.MarshalDeterministic`
(or equivalent). Each proof entry is a typed sub-message; new
proof types require a `.proto` schema bump.

- **Verifier-implementation difficulty: low for "blessed" languages,
  medium for others.** Go, Python, TypeScript and Rust all have
  protobuf bindings, but the verifier needs the *current*
  `.proto` to decode. A verifier built against v1 .proto cannot
  even *parse* a v2 bundle's `oneof` arm if v2 added a new arm —
  protobuf will surface `unknown field` for v3 messages, but a
  `oneof` over typed sub-messages is more brittle: the verifier
  must explicitly tolerate the unknown-arm case in code.
- **Version evolution: poor for `oneof`-shaped schemas, decent
  for scalar-tag shaped schemas.** A clean evolution requires
  treating each new proof type as an additive field rather than a
  `oneof` arm, which loses the type-safety appeal of protobuf in
  the first place. The compromise is to model the proof entry as
  `(uint32 proof_type_tag, bytes payload)` — at which point we
  have re-implemented Option 1's open-tag scheme inside protobuf
  and lost the schema's expressiveness.
- **Signature surface: protobuf canonical encoding is not
  guaranteed.** Protobuf v3 deliberately does not specify a
  canonical encoding (the spec says implementations MAY produce
  different byte sequences for the same logical message). Go's
  `protowire.MarshalDeterministic` is one library's *attempt*;
  Python's `proto.SerializeToString(deterministic=True)` is
  another; the two are not byte-identical for messages
  containing `map<>` or unknown fields. Cross-language signature
  verification therefore requires extra normalisation that the
  spec does not bless.
- **Opaque-byte handling: native (`bytes` field type).** Same as
  Option 1 in this respect.
- **Schema-evolution mode: closed.** Adding a proof type is a
  schema change shipped via a `buf` lint pass (the workspace
  already uses `buf`), not a registry update.
- **Bundle size: comparable to CBOR.** Protobuf is generally
  slightly more compact than deterministic CBOR for typed
  fields and slightly larger for byte-heavy payloads (because
  CBOR uses single-byte type framing). Difference is in the
  noise.
- **Tooling friction: medium.** The wallet emits the bundle via
  `prost = 0.13` (workspace pin) and ships the `.proto` to every
  verifier. Protobuf code-gen is fine for first-party verifiers
  but adds a build step for ad-hoc audit tooling.
- **Footgun: cross-language canonical encoding drift.** A bundle
  emitted by the Rust prover, re-encoded by a Go verifier, then
  re-encoded by a Python verifier — the three byte sequences are
  *not* guaranteed to match. The signature can verify against
  the original bytes only if the verifier preserves the wire
  bytes exactly (no decode/re-encode round trip). This is doable
  in principle but turns the parser into a "byte-range reader",
  which is fragile.
- **Cross-cutting risk: high.** The workspace already uses
  protobuf for the gRPC services (`proto/ark/v1/*.proto`), and
  using protobuf for the bundle would let us reuse the
  `dark-api` build pipeline. *But* the gRPC schema is internal
  (operator ↔ wallet) where canonical-encoding is irrelevant
  (the receiver verifies against TLS), whereas the bundle is a
  signed cross-organisational artefact where canonical-encoding
  IS the load-bearing property. The two use cases pull in
  opposite directions on this axis.

### Option 3 — JSON with RFC 8785 (JCS) canonicalisation, open tag registry, signed pre-image is JCS-canonical UTF-8 bytes

The bundle is a JSON document. Canonicalisation follows RFC 8785
(JSON Canonicalization Scheme): sort object members lexicographically
by codepoint, normalise number representation to ECMA-262 §6.1.6.1,
escape exactly the characters JSON.parse mandates. Opaque payloads
are base64-encoded. The signed message is
`SHA256(jcs_canonicalize(<signed_subset>))`.

- **Verifier-implementation difficulty: very low to parse, medium
  to canonicalise.** Every language has a JSON parser; very few
  have a *correct* JCS canonicaliser. Rust's `serde_jcs` exists
  but is a third-party crate at ~v0.1; Python has `pyjcs`
  (third-party); Go has a couple of small libraries but no
  blessed one. JCS correctness bugs are subtle (number
  normalisation in particular — `1.0` vs `1` is a distinguishing
  case) and have caused real cross-implementation signature
  mismatches in the JOSE / Verifiable Credentials world.
- **Version evolution: open and easy.** The proof-type tag is a
  numeric or string field in a JSON object. Old verifiers
  ignore unknown tags by structural traversal.
- **Signature surface: JCS-dependent.** A bug in any verifier's
  JCS implementation (number rounding, codepoint sorting,
  Unicode normalisation) breaks signature verification across
  implementations. The "every verifier has its own subtly
  different canonicaliser" failure mode is not hypothetical;
  it is the dominant pain point in the JOSE-VC ecosystem.
- **Opaque-byte handling: textual (base64 + length).** Every
  opaque payload incurs a 4/3× size overhead from base64 plus
  the JSON string-quote framing. For a 700 B Bulletproofs blob
  this is ~940 B encoded, vs. ~700 B in CBOR. Not catastrophic
  for compliance bundles (we are not in the hot loop) but a
  meaningful overhead for `BoundedRange`-heavy bundles.
- **Schema-evolution mode: open.** Like Option 1.
- **Bundle size: ~1.4× CBOR for typical payloads.** Mostly
  base64 overhead.
- **Tooling friction: low to parse, medium to verify.** Hand-rolled
  audit tooling can parse a bundle in five lines of any
  language's stdlib, but cannot verify the signature without
  pulling a JCS library.
- **Footgun: JCS interoperability.** This is the killer point.
  We accept that bundles will be verified by tooling we did not
  write; if even one of those implementations has a
  number-canonicalisation bug, valid bundles will be rejected.
  The CBOR deterministic-encoding profile has the same risk in
  principle, but in practice CBOR's encoding rules are simpler
  (no number normalisation in scientific-notation, no Unicode
  normalisation, no string-escape ambiguity) and the conformance
  bar is much lower.
- **Cross-cutting risk: low.** No protobuf coupling; no shared
  schema discipline required.

### Evaluation matrix

| Criterion | Opt 1 (CBOR) | Opt 2 (protobuf) | Opt 3 (JSON+JCS) |
|---|---|---|---|
| Off-the-shelf parser in Rust / Go / Python / TS | Yes (4/4) | Yes (4/4) | Yes parse; JCS canonicaliser is third-party (4/4 partial) |
| Deterministic encoding spec strength | Strong (RFC 8949 §4.2.1) | Implementation-defined; differs per binding | Strong (RFC 8785) but error-prone |
| Cross-language signature stability | High (re-canonicalise on verify) | Low (binding-dependent) | Medium (JCS bugs are common) |
| Open tag registry without schema bump | Yes (CBOR map keys are integers) | Awkward (`oneof` is closed; need `(tag, bytes)` pair → reinvents Opt 1) | Yes (JSON keys) |
| Opaque-byte handling | Native bytes | Native bytes | base64 (~33% overhead) |
| Bundle size (typical) | Smallest | Comparable | ~1.4× CBOR |
| Verifier crash on unknown proof type | Skip entry, continue | Risk of `oneof` parse error if old binding | Skip entry, continue |
| Existing workspace dep | `ciborium` (already used by ADR-0003) | `prost` (already used by gRPC) | None (would add `serde_jcs` or similar) |
| Suitability for cross-organisational signed artefact | Excellent | Poor (canonical encoding not spec-mandated) | Medium (JCS conformance risk) |
| Tooling needed for ad-hoc audits | `cbor` decode + Schnorr verify | `protoc` + generated code + Schnorr verify | `json` decode + JCS lib + Schnorr verify |
| Audit surface (lines of envelope code) | Small (~150 LoC Rust) | Medium (~250 LoC Rust + .proto) | Small to parse, medium to canonicalise |
| Failure mode on misimplemented canonicaliser | Verifier rejects mismatched bundle (typed error) | Verifier accepts mismatched bytes (silent corruption) | Verifier rejects mismatched bundle (typed error) |
| Coupling to existing infrastructure | Low (memo path) | High (gRPC) | Zero |
| Future-extension cost | Registry update | Schema PR + buf-lint | Registry update |

## Decision

**Adopt Option 1** — deterministic CBOR per RFC 8949 §4.2.1 with an
open numeric proof-type tag registry pinned in this ADR, signed by
the issuer with a BIP-340 Schnorr signature over the SHA-256 of the
canonical CBOR bytes of the signed subset.

The rationale is that the bundle is a **cross-organisational signed
artefact** whose entire job is to verify identically against any
honest third-party verifier. Option 2 (protobuf) loses on this axis
because protobuf v3's wire encoding is explicitly not canonical, and
the cross-language drift is a documented foot-gun; Option 3 (JCS)
preserves cross-implementation signature stability in principle but
inherits the well-known JCS interoperability tax in practice. CBOR's
deterministic-encoding profile is the simplest of the three (no
number-normalisation, no Unicode-canonicalisation, no string-escape
ambiguity) and is implemented faithfully by every major
language's CBOR library. The opaque-bytes handling is also native
(no base64), which matters for `BoundedRange` and any future
zero-knowledge proof type that ships a binary blob.

### Wire layout

A `ComplianceProofBundle` is a deterministic CBOR map with exactly
three top-level fields. The map keys are CBOR unsigned integers, not
strings, both for compactness and to remove any ambiguity about
case-folding or Unicode-normalisation in the canonical pre-image.

```text
ComplianceProofBundle = {
    1: BundleHeader,            # header (typed map; see below)
    2: [ + ProofEntry ],        # one or more proof entries (CBOR array)
    3: IssuerSignature,         # 64-byte Schnorr signature over the canonical pre-image
}
```

The map MUST contain exactly these three keys, in this order under
deterministic encoding (sorted ascending by integer key). A bundle
with extra top-level keys MUST be rejected with
`BundleParseError::UnknownTopLevelKey { key: <int> }`.

### `BundleHeader`

```text
BundleHeader = {
    1: u16,                                    # version (currently 1)
    2: u16,                                    # min_supported_version (issuer's lower bound)
    3: bytes(32),                              # scope_binding_hash (see below)
    4: [ + u32 ],                              # included_proof_types (sorted ascending tag list)
    5: u64,                                    # issuance_timestamp (UNIX seconds, signed)
    6: bytes(32),                              # nonce (32 fresh CSPRNG bytes)
    7: bytes(32),                              # issuer_pubkey_xonly (BIP-340 x-only)
    8: AuditorBinding,                         # auditor binding (typed; "absent" tag if unbound)
    9: bool,                                   # requires_all_known_types
    10: u64,                                   # max_payload_bytes (issuer's stated ceiling per entry)
}
```

Every field is mandatory. The `included_proof_types` array is the
sorted ascending list of `proof_type_tag` values that the bundle's
entries claim to use; verifiers MUST cross-check this list against
the actual entries and reject mismatches with `BundleParseError::IncludedProofTypeMismatch`.
Carrying the list explicitly lets a verifier short-circuit on
"this bundle has a tag I don't know" before parsing each entry.

#### `scope_binding_hash`

A 32-byte SHA-256 hash that pins the bundle to a declared scope. The
pre-image is a deterministic-CBOR-encoded structure:

```text
ScopeBindingPreimage = {
    1: u32,                  # scope_kind: 0=RoundRange, 1=VtxoSet, 2=AccountAndTimeWindow
    2: ScopeKindPayload,     # depends on scope_kind
}
```

Where `ScopeKindPayload` is one of:

- `scope_kind = 0` (RoundRange):
  ```text
  { 1: u64 first_round_id, 2: u64 last_round_id }
  ```
- `scope_kind = 1` (VtxoSet):
  ```text
  { 1: [ + bytes(32) ] }   # sorted ascending list of vtxo_id digests (SHA-256 of the canonical "txid:vout" UTF-8 bytes)
  ```
- `scope_kind = 2` (AccountAndTimeWindow):
  ```text
  { 1: u32 account_index, 2: u64 window_start_unix, 3: u64 window_end_unix }
  ```

The wallet computes
`scope_binding_hash = SHA256(canonical_cbor(ScopeBindingPreimage))`
and signs over this 32-byte hash, NOT the pre-image itself. This is
load-bearing for two reasons: (1) it lets the verifier cheaply
recompute the hash from publicly-known scope metadata without the
bundle's having to inline the entire pre-image, and (2) it
decouples the scope schema from the bundle's wire schema — a future
ADR can introduce `scope_kind = 3, 4, …` without bumping the bundle
version, because the hash is opaque from the bundle's perspective.

#### `included_proof_types`

A CBOR array of unsigned integers, sorted ascending, with no
duplicates. Each entry is a `proof_type_tag` (see "Proof-type tag
registry" below). The verifier MUST reject the bundle if the array
is empty (an empty bundle is meaningless) and MUST reject if any
entry's `proof_type_tag` is missing from the array or vice versa.

#### `auditor_binding`

A typed sub-map with two arms:

```text
AuditorBinding = {
    1: u32 binding_kind,       # 0=Absent, 1=Pubkey, (future: 2=PubkeySet, 3=NamedAuditor)
    2: AuditorBindingPayload,
}
```

For `binding_kind = 0` (Absent):

```text
AuditorBindingPayload = null   # CBOR major type 7, value 22 (`null`)
```

For `binding_kind = 1` (Pubkey):

```text
AuditorBindingPayload = bytes(32)    # auditor's BIP-340 x-only pubkey
```

The "Absent" arm uses an explicit CBOR `null` rather than omitting
the field — this is what makes the auditor-binding pre-image
unambiguous under canonical encoding. A bundle with no auditor
binding MUST encode `binding_kind = 0` and `payload = null`; it
MUST NOT omit field `8`.

The auditor binding does NOT verify the auditor's signature on
anything — the auditor never countersigns the bundle. It exists
purely to bind the issuer's signature to *which auditor this bundle
is intended for*. A malicious auditor cannot strip the field and
replay (because `auditor_binding` is in the signed pre-image) and
cannot replace it with a different pubkey (same reason). The
verifier MUST therefore check that the `auditor_binding` field
matches the verifier's own identity (when it has one) and surface
`BundleVerifyError::AuditorBindingMismatch` otherwise.

#### `requires_all_known_types`

When `true`, a verifier that encounters any unknown
`proof_type_tag` MUST reject the bundle as a whole with
`BundleVerifyError::UnknownProofTypeStrict`. When `false` (default),
the verifier MUST process every entry whose tag it knows, mark
unknown-tag entries as `Skipped`, and surface a per-entry
`VerificationOutcome::Skipped { reason: UnknownProofType { tag } }`
in the verification result.

The strict mode exists for regulatory contexts where the auditor
cannot accept a partial verification — they need either "every
claim in this bundle verifies" or a hard fail. The default mode
(`false`) is for institutional audits where the auditor is
willing to extract whatever they can verify and triage the rest
out-of-band.

#### `max_payload_bytes`

The issuer's stated upper bound on `payload` size for any entry in
the bundle. The verifier MUST cross-check each entry's payload
length against this bound and reject mismatches. This is a defence
against an attacker who tries to craft an oversized payload that
slips past the verifier's *default* `MAX_ENTRY_BYTES` because the
issuer claimed a larger ceiling. The smaller of (verifier's
`MAX_ENTRY_BYTES`, header's `max_payload_bytes`) is the effective
cap.

### `ProofEntry`

```text
ProofEntry = {
    1: u32,                                    # proof_type_tag (see registry below)
    2: bytes,                                  # opaque proof payload (length ≤ max_payload_bytes)
    3: bytes(32),                              # vtxo_or_round_ref (sha256 of canonical reference)
    4: u64,                                    # entry_issuance_timestamp (UNIX seconds; per-entry, signed)
    5: u32,                                    # payload_schema_version (proof-type-specific minor version)
}
```

Every field is mandatory. The `vtxo_or_round_ref` is a SHA-256
hash that pins the entry to its target — for `VtxoReveal`, this is
`SHA256(canonical_utf8("vtxo:" || vtxo_id))`; for
`ViewingKeyIssuance`, this is the scope-binding-hash for the issued
scope; for `BoundedRange`, the same as `VtxoReveal`; for
`SourceOfFunds`, `SHA256(canonical_utf8("source:" || subject_vtxo_id || ":" || ancestor_vtxo_id))`.
Per-proof-type ADRs (#564, #565, #566, #567) pin the exact pre-image
strings.

The `payload_schema_version` is the **proof-type-specific** minor
version. The bundle's outer `version` field tracks the *envelope*;
the per-entry `payload_schema_version` lets a single proof-type
evolve its inner payload independently of the envelope. A
`VtxoReveal` v1 payload and a `VtxoReveal` v2 payload coexist in
the same envelope version 1, distinguished by this field.

### Proof-type tag registry

| Tag | Name | Owner ADR / Issue | MVP / Stretch | Payload schema version |
|---:|---|---|---|---|
| 1 | `VtxoReveal` | #565 | MVP | 1 |
| 2 | `ViewingKeyIssuance` | #564 / `m6-dd-viewing-scope` | MVP | 1 |
| 3 | `BoundedRange` | #566 | Stretch | 1 |
| 4 | `SourceOfFunds` | #567 / `crates/dark-core/src/compliance.rs` | Stretch | 1 |
| 5–99 | reserved for M6 follow-ups | — | — | — |
| 100–199 | reserved for M7 zero-knowledge proof types | — | — | — |
| 200–999 | reserved for future milestones | — | — | — |
| 1000–4_294_967_294 | open registration | — | — | — |
| 4_294_967_295 (`u32::MAX`) | RESERVED — never issue | — | — | — |

Tags `0` and `u32::MAX` are reserved sentinels. `0` is reserved
for "absent / placeholder" semantics in any future field that
needs an "absent tag" encoding. `u32::MAX` is reserved as a
"never-issue" canary so a buggy verifier that defaults its tag
field to `0xFFFFFFFF` cannot accidentally match a real proof type.

The reserved-range scheme exists because we expect proof-type
tagspace to be small (single-digit additions per milestone) and
the auditor-side tooling tends to hard-code "this is the tag I
expect" lookups; a regimented range structure is more readable
than a flat numeric soup.

### `IssuerSignature`

```text
IssuerSignature = bytes(64)    # BIP-340 Schnorr signature
```

The signing pre-image is `SHA256(SignedSubsetCanonicalCBOR)`, where
`SignedSubsetCanonicalCBOR` is the canonical CBOR encoding of:

```text
SignedSubset = {
    1: BundleHeader,
    2: [ + ProofEntry ],
}
```

Note that the `IssuerSignature` field itself is NOT in the signed
subset (signing-over-self is undefined). The verifier:

1. Parses the bundle map. Rejects any extra top-level keys.
2. Re-encodes the signed subset under deterministic CBOR. This is
   the load-bearing step that protects against a sender that
   produced *valid* but *non-canonical* CBOR — the verifier always
   re-canonicalises before hashing.
3. Computes `signing_message = SHA256(SignedSubsetCanonicalCBOR)`.
4. Verifies the BIP-340 Schnorr signature against
   `header.issuer_pubkey_xonly` and `signing_message`.

The signature scheme is BIP-340 Schnorr over secp256k1. The
issuer's signing key is derived under the path
`m/44'/1237'/{account}'/2'/0` — a *new* role component (`2'`) added
to ADR-M5-DD-stealth-derivation's path layout, sibling to
`scan` (`0'`) and `spend` (`1'`). Adding a third hardened role
component is a v1.x change to ADR-M5-DD-stealth-derivation;
**[FU-CB-DERIV]** tracks that companion update so the path is not
silently introduced here.

The reason for a separate role is the same reason scan and spend
are separate roles: a leak of the issuer signing key reveals the
wallet's history of compliance disclosures (already public to the
auditor, but linkable across auditors) without endangering funds.
A leak of `spend_sk` would let the holder forge bundles attributed
to the issuer; the path separation prevents that compromise from
propagating.

### Canonical CBOR encoding contract

The reference parser MUST enforce the deterministic-encoding rules
of RFC 8949 §4.2.1 on both encode and re-encode (verify) paths:

- All `map` keys are CBOR unsigned integers (major type 0). No
  text-key maps anywhere in the bundle.
- Map keys MUST be sorted ascending by numeric value before
  encoding. On decode, a verifier that sees an out-of-order map
  MUST reject with `BundleParseError::NonCanonicalKeyOrder`.
- Definite-length encoding MUST be used for all arrays, maps,
  and byte/text strings. Indefinite-length forms (CBOR major
  type 7 markers) MUST be rejected on decode.
- Integer encoding MUST use the shortest form (major types 0/1
  with the smallest argument representation). A `u64 = 5`
  encoded as a 9-byte form MUST be rejected with
  `BundleParseError::NonCanonicalInteger`.
- No CBOR tags (major type 6) anywhere. The bundle does not use
  semantic tags; their absence is part of the canonical contract.
  A bundle that carries any major-type-6 element MUST be rejected.
- No floating-point values (major type 7 with float subtypes).
  All numeric fields are unsigned integers. A bundle that
  carries a float MUST be rejected.

These rules are stricter than CBOR's deterministic-encoding profile
strictly requires (the standard profile permits text-key maps and
some semantic tags); we tighten them so the bundle's canonical
form has zero ambiguous corners.

### Default size limits

- `MAX_BUNDLE_BYTES = 1_048_576` (1 MiB). Rationale: a bundle with
  ~10 `BoundedRange` entries (≈700 B Bulletproofs each) plus a
  large `SourceOfFunds` (depth-32, ≈4 KiB) plus envelope overhead
  is ~12 KiB. The 1 MiB ceiling leaves >80× headroom for future
  proof types while bounding the parser's allocation budget.
- `MAX_ENTRY_BYTES = 262_144` (256 KiB). Per-entry cap.
- `MAX_ENTRIES = 256`. Per-bundle cap on number of `ProofEntry`
  elements.

The verifier MUST reject any bundle violating any of these limits
with a typed `BundleParseError::SizeLimitExceeded { limit, actual }`
before further parsing.

### Specification

The canonical specification, in pseudo-Rust, lives in
`crates/dark-confidential/src/disclosure.rs` (currently a stub) and
is owned by #565 (which lands the first concrete proof type).
Behavioural contract:

```rust
// pseudocode — implementation lives in #565 onwards
pub struct BundleHeader {
    pub version: u16,
    pub min_supported_version: u16,
    pub scope_binding_hash: [u8; 32],
    pub included_proof_types: Vec<u32>,        // sorted ascending, deduplicated
    pub issuance_timestamp: u64,
    pub nonce: [u8; 32],
    pub issuer_pubkey_xonly: [u8; 32],
    pub auditor_binding: AuditorBinding,
    pub requires_all_known_types: bool,
    pub max_payload_bytes: u64,
}

pub struct ProofEntry {
    pub proof_type_tag: u32,
    pub payload: Vec<u8>,                       // opaque to envelope
    pub vtxo_or_round_ref: [u8; 32],
    pub entry_issuance_timestamp: u64,
    pub payload_schema_version: u32,
}

pub struct ComplianceProofBundle {
    pub header: BundleHeader,
    pub entries: Vec<ProofEntry>,               // 1..=MAX_ENTRIES
    pub issuer_signature: [u8; 64],             // BIP-340 Schnorr
}

pub enum AuditorBinding {
    Absent,
    Pubkey([u8; 32]),
}

pub fn encode(bundle: &ComplianceProofBundle) -> Result<Vec<u8>, EncodeError> {
    // ciborium with Config { float_encoding: Reject, sort_keys: Ascending }
    // assert_no_indefinite_lengths, assert_no_tags
}

pub fn decode(bytes: &[u8]) -> Result<ComplianceProofBundle, DecodeError> {
    // strict canonical-CBOR mode
}

pub fn signing_message(header: &BundleHeader, entries: &[ProofEntry])
    -> Result<[u8; 32], EncodeError>
{
    // Sha256(canonical_cbor_of(SignedSubset { header, entries }))
}

pub fn verify(
    bundle: &ComplianceProofBundle,
    public_round_data: &dyn PublicRoundData,
    verifier_options: &VerifierOptions,
) -> VerificationResult { /* ... */ }

pub struct VerificationResult {
    pub overall: Result<(), BundleVerifyError>,
    pub per_entry: Vec<EntryOutcome>,           // one per entry, in order
}

pub enum EntryOutcome {
    Verified { proof_type_tag: u32 },
    Skipped  { proof_type_tag: u32, reason: SkipReason },
    Failed   { proof_type_tag: u32, error: ProofTypeError },
}
```

The verifier MUST be a pure function of `(bundle_bytes,
public_round_data, verifier_options)` — no I/O on the verification
path beyond the public-round-data oracle, which is itself
read-only.

### Test vectors

Six placeholder vectors are stubbed at this ADR's land time at
`docs/adr/vectors/m6-compliance-bundle-vectors.json`. The vector
contents are filled byte-exactly as each downstream issue lands:

| Vector | Filled by | Description |
|---|---|---|
| V1 | #565 | Single-entry bundle: one `VtxoReveal` for a known VTXO. |
| V2 | #564 | Single-entry bundle: one `ViewingKeyIssuance` for a 100-round scope. |
| V3 | #565 + #564 | Multi-entry bundle: one `VtxoReveal` + one `ViewingKeyIssuance`. |
| V4 | #565 | Negative: signature byte-flipped → `InvalidSignature`. |
| V5 | this ADR | Negative: bundle with `proof_type_tag = 99` (reserved range, no proof type defined) → `Skipped { UnknownProofType }` per entry. |
| V6 | this ADR | Negative: bundle with `version = 2`, verifier at v1 → `UnsupportedVersion`. |

Vector V5 is materialised in this ADR's land commit because it
exercises the envelope-only path (unknown tag with known envelope);
it does not depend on any proof-type implementation. Vector V6 is
also materialised here for the same reason. Vectors V1–V4 wait on
the proof-type implementations.

The vector generator lives at `contrib/compliance-bundle-vector-gen/`
(created by #565), reuses the `ciborium = 0.2` and
`secp256k1 = 0.29` workspace pins, and produces deterministic
output given the same input scalars.

## Versioning

The bundle's `version` field is a `u16` starting at `1` for the
launch format. The `min_supported_version` field is the issuer's
explicit lower bound — verifiers below this version MUST reject the
bundle with `BundleVerifyError::UnsupportedVersion`. The bumps are
governed by the following rules:

### v1 verifier facing a v2 bundle

A verifier whose `MAX_SUPPORTED_VERSION = 1` parses the bundle's
top-level map far enough to read `header.version`. If
`header.version > 1`, the verifier:

1. Rejects with `BundleVerifyError::UnsupportedVersion { received: 2, supported_max: 1 }`.
2. Does NOT parse any proof entries.
3. Does NOT verify the signature (the signed subset's canonicalisation
   MAY have changed in v2, so a v1 verifier's re-encoding would
   produce a different pre-image, and a "signature failed" error
   would mask the real cause).
4. Surfaces the typed error to the caller. The caller (e.g. the
   `ark-cli verify-proof` command) prints
   `"Bundle is version 2; this verifier supports up to version 1.
   Upgrade your tooling."` — never silently treats the bundle as
   unverified.

### v2 verifier facing a v1 bundle

A verifier whose `MAX_SUPPORTED_VERSION = 2` and whose
`MIN_SUPPORTED_VERSION = 1` reads `header.version = 1` and:

1. Dispatches to the v1 verification path. v1 and v2 are not
   merged into a single code path — each version is its own
   implementation, sharing the proof-type-specific verifiers but
   not the envelope parser.
2. The v1 verification path is **frozen** at the day v2 ships.
   Any bug in the v1 path is fixed only with a v1.x point-release
   that does not change the canonical encoding (i.e.
   strict-error-handling fixes only; behaviour-preserving).

### v2 verifier facing a v2 bundle whose `min_supported_version = 2`

The verifier's `MAX_SUPPORTED_VERSION` includes 2; verifies
normally.

### v2 verifier facing a v1 bundle whose `min_supported_version = 0`

`min_supported_version = 0` is reserved for "any verifier"
semantics (the issuer is willing to be verified by an arbitrarily
old verifier). v2 verifiers process the bundle on the v1 path.
A v0 path is not defined in this ADR; `min_supported_version = 0`
is therefore a forward-pointing affordance for ADR authors who
later need a "best effort, any version" mode.

### What may change between v1 and v2

The v1→v2 boundary is where envelope-shape changes happen. Among
the changes that REQUIRE a version bump:

- Adding, removing, renaming, or reordering any `BundleHeader`
  field. Per the canonical-encoding rules, integer keys are
  load-bearing; reusing a key for different semantics in v2 is
  forbidden.
- Changing the canonical-CBOR rules (e.g. allowing semantic tags,
  permitting indefinite-length encoding).
- Changing the signing-message construction (e.g. moving from
  SHA-256 to BLAKE2b; changing the signed-subset shape).
- Changing the signature scheme (e.g. BIP-340 Schnorr → MuSig2 or
  a future post-quantum scheme).
- Changing the `MAX_BUNDLE_BYTES` / `MAX_ENTRY_BYTES` defaults
  upward in a way that older verifiers would silently accept
  oversized bundles.

### What may change WITHIN v1

Additive registry updates do NOT bump the envelope version:

- Allocating a new `proof_type_tag` from the reserved or open
  range.
- Defining a new `ScopeKindPayload` arm (e.g. `scope_kind = 3`).
- Defining a new `AuditorBinding` `binding_kind` arm. Verifiers
  MUST tolerate unknown `binding_kind` values by surfacing
  `BundleVerifyError::UnknownAuditorBindingKind { kind }`; this
  is one of the few places where the envelope itself rejects on
  unknown rather than skipping (because the auditor binding is
  load-bearing for replay defence and "I don't understand the
  binding" is not safe to silently accept).
- Bumping a per-proof-type `payload_schema_version` (e.g.
  `VtxoReveal` v1 → `VtxoReveal` v2). Old verifiers handle this
  by rejecting the entry with `ProofTypeError::PayloadSchemaTooNew
  { tag: 1, expected_max: 1, received: 2 }` and continue
  processing other entries.

### How the registry update mechanism works

Allocating a tag from the open range (`1000` and above) requires:

1. A merged ADR or design issue in the `compliance` /
   `selective-disclosure` label that names the proof type, its
   payload schema, its `vtxo_or_round_ref` pre-image, and its
   acceptance criteria.
2. A PR to `dark-confidential::disclosure` adding the
   proof-type-specific verifier behind a feature flag.
3. A PR to *this* ADR that adds the new tag to the registry
   table above. This is an additive change to the ADR; it does
   NOT bump the bundle version.

Steps 1–3 happen in any order; step 3 is the canonical record. A
proof type whose tag does not appear in the registry is by
definition "unknown" to a conforming verifier and triggers the
unknown-tag handling described in "Decision".

## Cross-cutting constraints

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen this ADR before landing.

### #563 (M6 launch scope ADR) MUST

- Pin tags `1` (`VtxoReveal`) and `2` (`ViewingKeyIssuance`) as
  the MVP launch set, matching the registry above.
- Document tags `3` (`BoundedRange`) and `4` (`SourceOfFunds`) as
  stretch / behind-feature-flag, matching the registry above.
- Reserve `5–99` for M6 follow-ups in a way consistent with this
  ADR's reserved range.

### #563 MUST NOT

- Allocate a proof-type tag without a registry entry in this ADR.
- Re-use an already-allocated tag for a different proof type.

### #565 (`VtxoReveal` proof) MUST

- Encode the `VtxoReveal` payload as deterministic CBOR with
  fields `{ 1: u64 amount, 2: bytes(32) blinding, 3: u32 commitment_kind }`
  where `commitment_kind = 0` denotes the Pedersen commitment in
  ADR-0001 / #525.
- Compute `vtxo_or_round_ref = SHA256("vtxo:" || vtxo_id_utf8)`.
- Set `payload_schema_version = 1`.
- Sign the bundle with the issuer key derived at
  `m/44'/1237'/{account}'/2'/0` per this ADR's "Decision".
- Provide a property test asserting that
  `decode(encode(bundle)) == bundle` for every well-formed bundle
  under proptest.
- Reject decode on any non-canonical CBOR encoding (out-of-order
  map keys, indefinite-length, redundant integer encoding).

### #565 MUST NOT

- Embed the wallet's long-lived spend pubkey in the
  `VtxoReveal` payload. The `vtxo_or_round_ref` already pins the
  VTXO; the auditor does not need spending authority.
- Allow a `VtxoReveal` payload that opens more than one VTXO. A
  bundle that wishes to disclose two VTXOs MUST emit two
  `VtxoReveal` entries.
- Use any encoding other than deterministic CBOR for the payload.
- Reuse the `nonce` from one bundle in another. The nonce is
  CSPRNG-fresh per bundle.

### #564 (`ViewingKeyIssuance` proof) MUST

- Encode the payload as deterministic CBOR with fields
  `{ 1: bytes(32) viewing_key_pubkey_xonly, 2: ScopeBindingPreimage scope, 3: u64 expiry_unix }`.
- Set `vtxo_or_round_ref = scope_binding_hash` from the header
  (i.e. the bundle's scope IS the issued scope).
- Set `payload_schema_version = 1`.
- Refuse to issue a viewing key whose `expiry_unix <
  issuance_timestamp + 60`. The 60-second floor is a sanity
  check; the wallet MAY enforce a higher floor.
- Refuse to issue a `ViewingKeyIssuance` whose `scope.scope_kind`
  the wallet itself does not implement (e.g. a wallet that does
  not support `AccountAndTimeWindow` MUST surface a typed error
  rather than emit a malformed bundle).

### #564 MUST NOT

- Embed the issuer's `spend_sk` or any byte derived from
  `spend_sk` in the payload. Viewing keys are derived from
  `scan_sk` per `m6-dd-viewing-scope`; the spend key never
  leaves the wallet.
- Allow a `ViewingKeyIssuance` whose declared scope outlives the
  enclosing bundle's intended audit window. The auditor's
  retention policy is theirs, but the issuer's `expiry_unix`
  bounds the cryptographic lifetime.

### #566 (`BoundedRange` proof) MUST

- Encode the payload as `{ 1: bytes range_proof_blob, 2: u64 max,
  3: u64 min }` (with `min = 0` for the unbounded-low case). The
  `range_proof_blob` is opaque from the bundle's perspective —
  the bundle parser does not look inside.
- Compute `vtxo_or_round_ref = SHA256("vtxo:" || vtxo_id_utf8)`,
  matching `VtxoReveal`.
- Gate behind the `compliance-proofs` feature flag if `m6-dd-launch-scope`
  has marked it deferred.
- Document the range-proof blob's schema in #566's accompanying
  ADR (out of scope for *this* ADR).

### #566 MUST NOT

- Embed the cleartext amount in the payload. The whole point of
  `BoundedRange` is that the amount is not revealed.
- Re-use a Bulletproofs blob across two bundles (the prover MUST
  resample randomness per proof to avoid generator-correlation
  attacks).

### #567 (`SourceOfFunds` proof) MUST

- Encode the payload as deterministic CBOR using the existing
  `crates/dark-core/src/compliance.rs::SourceOfFundsProof` struct,
  re-serialised through `ciborium` (the existing implementation
  uses `serde_json` for the signing message; this ADR pins
  CBOR for the bundle envelope and #567 MUST migrate the
  signing-message construction to CBOR before the bundle entry
  can ship).
- Compute `vtxo_or_round_ref = SHA256("source:" ||
  subject_vtxo_id_utf8 || ":" || ancestor_vtxo_id_utf8)`.
- Gate behind the `compliance-proofs` feature flag if deferred.

### #567 MUST NOT

- Reveal cleartext amounts at any hop. The proof's premise is
  amount-independent provenance.
- Embed the wallet's `scan_xprv` or `spend_xprv` in the chain
  signature. The chain signature is a single Schnorr signature
  over the canonical chain pre-image, signed by the per-bundle
  issuer key.

### #568 (`ark-cli` disclose / verify commands) MUST

- Emit bundle bytes as deterministic CBOR. The CLI MAY also
  emit a `--json` debug rendering of the parsed structure for
  human inspection, but the wire artefact (the file on disk
  passed to `verify-proof`) is CBOR.
- Print the bundle's `version`, `included_proof_types`,
  `scope_binding_hash` (hex), and `issuer_pubkey_xonly` (hex) in
  the human-readable default output.
- Surface a typed error with a clear remediation hint when a
  bundle's `version > MAX_SUPPORTED_VERSION` (per "Versioning").
- Accept bundles via stdin, file path, or base64-encoded
  argument; reject any non-CBOR input (e.g. a JSON file) with
  a typed error rather than a parse-error.

### #568 MUST NOT

- Re-encode a bundle on the verification path before signature
  checking — the verifier code path is the reference parser,
  which already re-canonicalises before hashing. Re-encoding at
  the CLI layer would duplicate (and risk diverging from) that
  step.
- Print the bundle's `nonce` field in human-readable output by
  default (it leaks no secret but adds clutter; show it under
  `--verbose`).

### #569 (`VerifyComplianceProof` gRPC endpoint) MUST

- Accept a single-field `ProofBundle { bytes bundle_bytes = 1 }`
  request whose payload is the deterministic-CBOR-encoded
  bundle. The bundle is opaque to the gRPC schema; the schema
  MUST NOT mirror the CBOR fields.
- Return a `VerificationResult` with the per-entry outcomes
  matching this ADR's `EntryOutcome` enum (mapped to a protobuf
  `oneof` for compatibility with the existing service).
- Surface `UnsupportedVersion` as a structured error, not a
  generic `Internal` (per #569's acceptance criterion 2).
- Be unauthenticated and rate-limited (per #569's task list).
- Log the bundle's hash (`SHA256(canonical_cbor_bytes)`) in the
  audit log. The full bundle bytes MUST NOT be logged by
  default — they may carry information the auditor considers
  sensitive even though the wallet disclosed it.

### #569 MUST NOT

- Decode the bundle into the gRPC schema. The bundle is CBOR;
  the gRPC layer MUST treat it as opaque bytes and pass them
  to the reference parser.
- Cache verification results across requests. The verifier is
  a pure function but bundle replay across organisational
  boundaries is the auditor's policy, not the operator's.

### Cross-cutting — invariants any new proof type MUST satisfy

Any future proof type added to the registry MUST:

- Have a registry entry in this ADR's table (additive ADR
  amendment).
- Define its `vtxo_or_round_ref` pre-image deterministically
  from public data.
- Define its payload as deterministic CBOR (this is a hard
  constraint; mixing payload encodings inside a CBOR envelope
  is forbidden because it complicates the canonical-bytes
  invariant).
- Provide at least one positive and one negative test vector in
  `docs/adr/vectors/m6-compliance-bundle-vectors.json`.
- Define its `payload_schema_version` semantics (rules for v1 →
  v2 migration).

## Open Questions / TODO

- **[FU-CB-DERIV]** — Companion update to ADR-M5-DD-stealth-derivation
  introducing the `2'` role component for the issuer signing key
  (`m/44'/1237'/{account}'/2'/0`). This ADR pins the path; the
  companion update is purely documentation alignment in the
  stealth-derivation ADR and a property-test addition to #553
  asserting the third role's disjointness from scan and spend.
- **[FU-CB-MUSIG]** — MuSig2 multi-signature issuer mode. Some
  institutional wallets are multi-party (e.g. exchange custody
  with two-of-three approvers). v1 ships single-Schnorr; a v1.x
  ADR amendment may register a `binding_kind = 4` (MultiPartyIssuer)
  arm of `IssuerSignature`'s implicit shape (the `IssuerSignature`
  field is currently a flat `bytes(64)`; MuSig2 fits in 64 bytes
  so the field shape does not need to change). What needs an ADR
  amendment is the cross-organisational ceremony spec, which is
  out of scope here.
- **[FU-CB-VECTORS-CROSS]** — Cross-implementation vector
  exchange. Once a second compliance-bundle implementation
  exists (e.g. a TypeScript audit SDK), the
  `m6-compliance-bundle-vectors.json` file MUST be re-run
  against it and any byte-mismatch reopens this ADR.
- **[FU-CB-AUDITOR-MULTI]** — Multi-auditor binding (`binding_kind
  = 2`, `PubkeySet`). A bundle that is intended to be verified by
  *any* of N named auditors. Requires the verifier's identity to
  be checked against set membership rather than equality. Out of
  scope for v1; one auditor at a time is the institutional norm.
- **[FU-CB-NAMED-AUDITOR]** — Named-auditor registry (`binding_kind
  = 3`, `NamedAuditor`) where the binding is a stable string
  identifier (e.g. an LEI code) rather than a pubkey. Useful when
  the auditor's pubkey rotates but their identity is stable.
  Requires an out-of-band auditor-name → pubkey resolver, which
  is itself a trust assumption. Tracked separately.
- **[FU-CB-EXPIRY]** — Bundle-level `expiry_unix` field. v1 has
  `issuance_timestamp` only; the verifier MAY enforce a
  freshness window via verifier policy, but the bundle does not
  carry a hard expiry. A v1.x amendment may add
  `header.expiry_unix` so the issuer can pin the cryptographic
  lifetime regardless of verifier policy. Adding this field is
  a v2 envelope bump (it is a new header field), tracked here
  for a future milestone.
- **[FU-CB-PQ]** — Post-quantum signature scheme migration.
  BIP-340 Schnorr is not PQ-safe. A future v2 envelope may
  carry a hybrid signature (Schnorr + Dilithium / SPHINCS+) or
  pivot wholesale to a PQ scheme. The path-derivation layer
  inherits whatever ADR-M5-DD-stealth-derivation's PQ migration
  decides; this ADR's signature surface is deliberately
  isolated to a single 64-byte field so the migration is local.
- **[FU-CB-RPC-AUTH]** — Authenticated `VerifyComplianceProof`
  variant. v1 #569 is unauthenticated (the verifier learns
  nothing the bundle does not already authorise); a future
  variant may bind the verification request to an auditor
  session for rate-limit accounting. Out of scope for #569's
  MVP; tracked here.
- **[FU-CB-EVAL-MATRIX-FILL]** — Cross-implementation
  evaluation against the matrix above (verifier-implementation
  difficulty, bundle-size on real workloads, signature stability
  under encoder-hopping). Requires at least two interoperating
  implementations; first opportunity is when a TypeScript audit
  SDK lands.

## References

- Issue #562 (this ADR)
- Issue #563 — M6 launch scope ADR (consumes the proof-type
  registry pinned here)
- Issue #564 — Viewing key derivation and scoped access (defines
  the `ViewingKeyIssuance` payload, consumes the bundle envelope)
- Issue #565 — VTXO selective reveal with commitment opening
  (defines the `VtxoReveal` payload, consumes the bundle envelope)
- Issue #566 — Bounded-range compliance proofs (defines the
  `BoundedRange` payload, gated behind feature flag)
- Issue #567 — Source-of-funds proofs over the linkable graph
  (defines the `SourceOfFunds` payload, gated behind feature flag)
- Issue #568 — `ark-cli disclose` / `verify-proof` commands
  (consumes the bundle envelope as the wire artefact)
- Issue #569 — `VerifyComplianceProof` gRPC endpoint (consumes
  the bundle envelope as opaque bytes)
- ADR-0001 — secp256k1-zkp integration strategy (curve choice;
  Pedersen commitments)
- ADR-0002 — nullifier derivation scheme (linkability domain
  unrelated to bundle issuer identity; bundles MUST NOT bridge)
- ADR-0003 — confidential VTXO memo format (defines the
  `(amount, blinding, one_time_spend_tag)` triple
  `VtxoReveal` opens; reuses `ciborium` as the workspace's
  CBOR library)
- ADR-M5-DD-stealth-derivation — stealth-address key derivation
  paths (provides the path-layout pattern this ADR extends with
  a third `2'` role for the issuer signing key)
- ADR-M5-DD-announcement-pruning — round announcement retention
  (defines the round identifiers `scope_kind = 0` references)
- RFC 8949 — Concise Binary Object Representation (CBOR);
  §4.2.1 deterministic encoding
- RFC 8785 — JSON Canonicalization Scheme (JCS) — referenced as
  Option 3, rejected
- BIP-340 — Schnorr signatures over secp256k1 (issuer signature
  scheme)
- `crates/dark-confidential/src/disclosure.rs` — stub module that
  the proof-type implementations build out against this ADR
- `crates/dark-core/src/compliance.rs` — existing source-of-funds
  proof scaffolding (#567 will migrate its signing-message path
  to CBOR per this ADR before the bundle entry ships)
- `proto/ark/v1/confidential.proto` — confidential-VTXO wire
  types (referenced for the `bytes`-payload pattern; the
  bundle envelope is NOT in this .proto file because it is CBOR,
  not protobuf)
- Test vectors:
  `docs/adr/vectors/m6-compliance-bundle-vectors.json`
  (created by this ADR's land commit; populated by #564/#565)
- Vector generator: `contrib/compliance-bundle-vector-gen/`
  (created by #565)
