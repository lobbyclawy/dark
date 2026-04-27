# Compliance guide: selective disclosure for institutional users

> **Audience.** Compliance officers, auditors, internal-control owners,
> and regulators evaluating Ark's confidential VTXO layer for use under
> regimes including the EU's **Markets in Crypto-Assets Regulation
> (MiCA)**, the **FATF Travel Rule** (Recommendation 16), and the U.S.
> **GENIUS Act** stablecoin disclosure requirements. This document is
> the operator-facing and auditor-facing companion to the cryptographic
> ADRs in [`docs/adr/`](../adr/), restated in regulatory language with
> worked end-to-end examples.
>
> **Status.** This guide describes the selective-disclosure surface
> shipping at the **CV-M6 milestone** of the dark project (the Rust
> implementation of the Ark protocol). It is **documentation only** —
> normative behaviour is pinned by the ADRs cross-referenced inline
> and by the source code under `crates/dark-confidential/`.
>
> **Non-goals (read this first).** Read [§9 — Explicit non-goals](#9-explicit-non-goals)
> before drawing any conclusion about what the system commits to.
> In particular: Ark is **not** a KYC system, the operator has **no
> back-door**, every disclosure is **user-initiated and voluntary**,
> and disclosing one VTXO does **not** disclose any other.

## Table of contents

1. [What is "selective disclosure" in Ark?](#1-what-is-selective-disclosure-in-ark)
2. [What the operator sees, and what it does not](#2-what-the-operator-sees-and-what-it-does-not)
3. [Disclosure types available at v1](#3-disclosure-types-available-at-v1)
4. [Lifecycle: bundle generation, hand-off, verification](#4-lifecycle-bundle-generation-hand-off-verification)
5. [Regulatory framings: Travel Rule, MiCA, GENIUS Act](#5-regulatory-framings-travel-rule-mica-genius-act)
6. [Threat model and limits of disclosure](#6-threat-model-and-limits-of-disclosure)
7. [Worked examples with `ark-cli`](#7-worked-examples-with-ark-cli)
8. [`VerifyComplianceProof` gRPC endpoint](#8-verifycomplianceproof-grpc-endpoint)
9. [Explicit non-goals](#9-explicit-non-goals)
10. [FAQ for auditors](#10-faq-for-auditors)
11. [References and cross-links](#11-references-and-cross-links)

---

## 1. What is "selective disclosure" in Ark?

The Ark protocol's **confidential VTXO layer** hides three pieces of
information that are visible in transparent UTXO chains: amounts (via
Pedersen commitments), recipient identities (via stealth addresses),
and the explicit balance graph (via nullifier-based spending; see
[ADR-0002](../adr/0002-nullifier-derivation.md)). The operator running
the Ark service learns *only* that some confidential VTXO was spent
inside a round; it does not learn the amount, the sender's real-world
identity, the recipient's real-world identity, or the link to any
fiat-on-ramp.

That property is desirable for users but creates a problem for
**institutional users** — funds, exchanges, custodians, regulated
issuers — who must satisfy obligations that other users do not face:

- **An exchange listing a confidential asset** must screen incoming
  deposits against AML rules (Travel Rule, sanctions lists).
- **A regulated issuer of an e-money token** must demonstrate to its
  national competent authority (NCA) that its outstanding tokens are
  fully reserve-backed (MiCA Title III, IV; GENIUS Act §4).
- **A counterparty in an OTC settlement** must receive proof that
  funds came from a clean source before accepting them.
- **An auditor performing periodic attestations** must reconcile the
  institution's books against on-chain activity.

A naive solution — make confidential VTXOs transparent for
institutions only — would give every institution a copy of every
user's payment history, which is the privacy regression the protocol
was designed to avoid. **Selective disclosure** is the alternative:
the user (or an institutional account-holder) **voluntarily** issues a
narrowly-scoped, cryptographically-bound proof that reveals **exactly
what the regulator or counterparty needs to see and nothing else**.

Three operating principles, applied throughout the rest of this guide:

1. **The wallet is the trust root.** Every disclosure is initiated by
   the holder of the spend key. There is no admin, oracle, or operator
   path that can compel disclosure on the user's behalf.
2. **Disclosure is per-bundle.** Each disclosure is a standalone,
   third-party-verifiable artefact (a "compliance bundle") that the
   user hands to one specific verifier. Two bundles for the same VTXO
   to two different auditors are cryptographically independent.
3. **Verification is operator-free.** Any third party with a copy of
   the bundle plus the public on-chain round commitments can verify
   it. The operator's `VerifyComplianceProof` gRPC endpoint
   ([§8](#8-verifycomplianceproof-grpc-endpoint)) is a convenience —
   it does the maths on the verifier's behalf — but the verifier may
   ignore it and run the same maths themselves.

The cryptographic decisions that make these properties hold are pinned
in the **ADRs that landed in milestone CV-M6**:

- [`docs/adr/m6-dd-disclosure-types.md`](../adr/m6-dd-disclosure-types.md)
  — closes the v1 disclosure-type registry (which proofs ship, which
  are deferred behind feature flags).
- [`docs/adr/m6-dd-compliance-bundle-format.md`](../adr/m6-dd-compliance-bundle-format.md)
  — pins the wire format (deterministic CBOR per RFC 8949 §4.2.1) and
  the canonical signing-message construction (BIP-340 Schnorr over
  SHA-256 of the canonical CBOR pre-image).
- [`docs/adr/m6-dd-viewing-key-scope.md`](../adr/m6-dd-viewing-key-scope.md)
  — pins the **epoch-bucketing** scope mechanism that bounds what a
  viewing key can decrypt and (critically) bounds the blast radius of
  a leak.

This guide cross-references those ADRs at every load-bearing claim.

---

## 2. What the operator sees, and what it does not

The single most common misconception about confidential VTXOs is that
"the operator can decrypt anything if it wants to". This is **not the
case**. The operator runs the round-coordination service; it sees the
public round commitments and the nullifier set. It does not hold any
secret key that opens commitments, decrypts memos, or rebuilds the
identity graph. There is no admin override.

This section enumerates what the operator does and does not see, with
pointers to the underlying cryptographic primitives.

### 2.1 What the operator sees

| Visible to operator             | Why it is visible                                                                             |
|---------------------------------|-----------------------------------------------------------------------------------------------|
| Round commitments               | Public on-chain artefact; required for any third party to verify a bundle without trusting the operator. |
| Nullifier set                   | Required to detect double-spends; per [ADR-0002](../adr/0002-nullifier-derivation.md) the nullifier is a deterministic function of the spend key but is **one-way** (the operator cannot invert a nullifier back to a spend key, a wallet, or an identity). |
| The "linkable graph"            | Each VTXO consumed in a round produces a known nullifier. The operator sees that *some* VTXO was spent and *some* output VTXO was produced; the binding from "input nullifier" to "output VTXO commitment" is public-by-construction. The operator does **not** see the amount or the recipient on either side. |
| Round-tree Merkle paths         | Necessary for the operator's own state-transition checks; published as part of round commitments so that any verifier can cross-check inclusion proofs in a `SourceOfFunds` bundle ([§3.4](#34-sourceoffunds-amlprovenance)). |
| The fact that round R existed   | Trivially. Round timing and size are not protected.                                           |

### 2.2 What the operator does *not* see

| Hidden from operator                       | How it is hidden                                                                                                                                                |
|--------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Amounts**                                | Pedersen-committed (`commit(amount, blinding) = amount·G + blinding·H`). The operator sees the elliptic-curve point; recovering `amount` requires knowing `blinding`, which only the holder of the spend key has. |
| **Recipient real-world identities**        | Stealth addresses ([ADR-M5-DD stealth derivation](../adr/0001-secp256k1-zkp-integration.md) ecosystem). Each output uses a fresh one-time public key derived from the recipient's published meta-address; the operator cannot link two outputs to the same recipient without the scan secret key. |
| **Memo contents**                          | AEAD-encrypted (ChaCha20-Poly1305) under a per-output key derived from ECDH between the sender's ephemeral key and the recipient's scan public key (see [ADR-0003](../adr/0003-confidential-memo-format.md)). The operator holds neither side of the ECDH. |
| **Sender ↔ recipient binding by identity** | Stealth addresses break the on-chain link; the operator sees only the one-time pubkey. The "this output belongs to wallet W" mapping lives off-chain in W's scanner. |
| **Amount sums, balances, holdings**        | A direct consequence of amount-hiding. The operator cannot compute "user X holds Y BTC" from public data. |
| **Source of funds beyond the previous hop**| The linkable graph is local: round R consumed nullifier N, produced output O. To trace O back to a fiat on-ramp, an external party would need either ([§3.4](#34-sourceoffunds-amlprovenance)) a `SourceOfFunds` proof from the user or the spend keys for every intermediate hop. The operator has neither. |
| **Counterparty relationships**             | A direct consequence of stealth addressing and memo encryption. |
| **The very fact that wallet W is using the system** | The operator sees per-round aggregate participation but cannot map a one-time pubkey back to a wallet identity. |

### 2.3 The operator has no back-door

This is worth stating explicitly because regulators sometimes assume
that a service operator must, by construction, hold a "master key"
that can decrypt user activity. Ark's confidential layer **does not**:

- The cryptography is **not key-escrow-based**. There is no per-user
  recovery key held by the operator.
- The cryptography is **not threshold-based** in a way that gives the
  operator a partial share. Balance proofs and range proofs are
  produced and verified using public-on-chain data plus the user's own
  blinding factors; the operator participates only as the publisher
  of round commitments.
- The cryptography is **not subject to a "lawful access" override**.
  No key in the system, anywhere, can be coerced to decrypt user
  amounts; lawful access requires either (a) a court order against the
  user that obtains the user's spend key, or (b) the user voluntarily
  issuing a disclosure bundle of the type described in this guide.

For a regulator: the consequence is that compliance enforcement under
a confidential VTXO regime works *exclusively through user-initiated
disclosure*, and the toolset for that disclosure is what the rest of
this guide describes.

---

## 3. Disclosure types available at v1

The v1 disclosure surface ships **three** proof types under the CV-M6
milestone, with a fourth (`SourceOfFunds`) reserved on the wire and
shipped behind a default-off feature flag pending its
end-to-end-test cycle. The closed v1 set is normative per
[`docs/adr/m6-dd-disclosure-types.md` §Decision](../adr/m6-dd-disclosure-types.md).

| Wire-tag (u16, BE) | Name                  | Status        | What it discloses to the verifier                                                |
|--------------------|-----------------------|---------------|----------------------------------------------------------------------------------|
| `0x0001`           | `ViewingKeyIssuance`  | **Ship**      | Decrypts every memo within a declared scope (round/epoch range) for one wallet.  |
| `0x0002`           | `VtxoReveal`          | **Ship**      | Opens `(amount, blinding)` for one specific VTXO; siblings unaffected.           |
| `0x0003`           | `BoundedRange`        | **Ship**      | Proves the committed amount of one VTXO satisfies a public bound (`< max`); does not reveal the amount. |
| `0x0004`           | `SourceOfFunds`       | **Reserved**, default-off feature flag | Proves a chain of nullifier-linked hops from a target VTXO back to a declared ancestor; reveals chain shape, not amounts. |

Tags `0x0005`–`0x0007` are pre-claimed for future
`AggregateBalanceThreshold`, `SetMembershipNotInSanctioned`, and
`MultiProofEnvelope` types; v1 verifiers reject them as
`UnknownProofType` in the same code path that handles literally-unknown
tags (see ADR §Backwards compat).

The next four subsections describe each shipping type at a level of
detail an auditor can take to a regulator. The cryptographic detail is
in the ADR; the operator/auditor framing is here.

### 3.1 `ViewingKeyIssuance` — auditor read-access for a fixed scope

**What it proves to the verifier.** That the bundle's payload is a
**scoped scan key**, signed by the holder of the spend key, that lets
the verifier decrypt the memos of every confidential VTXO addressed to
the user **inside the declared scope** (a contiguous epoch range,
where one epoch is a fixed-width window of rounds — see
[`docs/adr/m6-dd-viewing-key-scope.md` §Decision](../adr/m6-dd-viewing-key-scope.md)).

**What the verifier learns.** For each in-scope VTXO addressed to the
issuing wallet, the auditor recovers:

- The VTXO's amount.
- The blinding factor (so the auditor can independently recompute the
  Pedersen commitment and prove they are not making the amount up).
- The memo's free-form metadata, if the wallet wrote any (e.g. a
  trade ticket reference, an internal account label).
- The fact that this VTXO landed in a specific round inside the scope.

**What the verifier does *not* learn.**

- Anything about VTXOs outside the scope. The auditor's tooling
  literally cannot decrypt them, because the scoped scan key
  succeeds only against epoch-IDs in the issued range. The
  enforcement is **cryptographic, not procedural** — see
  [`docs/adr/m6-dd-viewing-key-scope.md` §Cryptographic enforcement, not tooling enforcement](../adr/m6-dd-viewing-key-scope.md).
- The user's spending authority. The viewing key cannot sign a
  spend; it is read-only by construction.
- VTXOs paid *from* the user (the viewing key derives from the user's
  *scan* key, which sees incoming payments; outgoing-payment metadata
  is not addressed to the user's scan key and is therefore invisible
  to the viewing key).

**Canonical institutional use case.** A periodic audit covering a
fixed reporting window — "Q3 2026 incoming-payment activity for
Account A". The user issues one viewing key for the relevant epoch
range to the auditor; the auditor decrypts every in-scope memo and
reconciles against the institution's books.

**Scope limit.** The viewing key MUST cover at least 1 epoch
(`MIN_SCOPE_EPOCHS = 1`) and at most 8192 epochs (`MAX_SCOPE_EPOCHS =
8192`, ≈ 16 years at the default 1024-rounds-per-epoch configuration).
The maximum exists to prevent accidental "view forever" issuance
(see ADR §Numerical bounds).

**Important caveat — viewing keys are forwardable.** A user who hands
a viewing key to Auditor A cannot prevent Auditor A from forwarding
the key to a third party. The bundle **is** the credential. This is a
direct property of the additive-tweak construction (see
[`docs/adr/m6-dd-viewing-key-scope.md` §Cross-cutting threat: collusion across two leaks](../adr/m6-dd-viewing-key-scope.md))
and it is documented to integrators as such. The mitigation is
operational (treat the viewing key like a wallet seed for the scope's
lifetime; the CLI prints a prominent warning at issuance time), not
cryptographic. A future v2 design (post-CV-M6) may use forward-secure
hierarchical IBE to remove the forwardability property; v1 ships the
additive-tweak scheme with the explicit caveat.

**Recovery on auditor-key leak.** If a viewing-key bundle is leaked
beyond its intended audience, the user's recovery is to **rotate the
master meta-address** — publish a new `MetaAddress` ([issue #553](https://github.com/lobbyclawy/dark/issues/553))
with a new `(scan_sk, spend_sk)` pair, and instruct counterparties to
use the new address. Past payments to the old meta-address remain
scannable by the leak attacker; future payments to the new meta-address
are not.

### 3.2 `VtxoReveal` — per-transaction selective disclosure

**What it proves to the verifier.** That the user knows the opening
`(amount, blinding)` of one specific committed VTXO, signed by the
holder of the spend key. The verifier independently recomputes
`commit(amount, blinding)` and constant-time-compares it against the
public on-chain `stored_commitment` for that VTXO. Equality is a
mathematical proof that the disclosed `(amount, blinding)` is the
exact opening of that commitment; the user has no way to disclose a
*wrong* amount that still verifies.

**What the verifier learns.**

- The exact amount of the named VTXO.
- The blinding factor (so the verifier reproduces the equality).
- The bundle's issuance timestamp (signed; replay-detectable).

**What the verifier does *not* learn.**

- Anything about sibling VTXOs in the same round. A reveal of VTXO V
  in round R does not help the verifier decrypt VTXO V' in the same
  round; commitments and memos are independent across VTXOs.
- Anything about descendants or ancestors of V in the linkable graph.
- The user's other holdings, balances, or transaction history.
- Spending authority (the bundle is signed by the spend key but the
  signature does not authorise a spend — see ADR §Audit notes for
  `VtxoReveal`).

**Canonical institutional use case.** "Prove you actually received
the 0.42 BTC settlement of trade T-2026-04-25-0042." The user issues a
single `VtxoReveal` bundle naming the VTXO id; the counterparty
verifies, books the trade, and stores the bundle as evidence.

**Property emphasised by ADR.** Per the bundle-format ADR §Threat model
("Auditor-only revelation"), revealing one VTXO MUST NOT enable the
verifier to learn anything about other VTXOs from the same wallet. The
cryptographic primitives (Pedersen commitments are independent under
fresh blindings; stealth-addressed one-time pubkeys are pseudorandom)
make this property hold by construction; the bundle format MUST NOT
re-introduce a wallet-wide identifier that would bridge the
unlinkability.

### 3.3 `BoundedRange` — Travel Rule threshold attestation

**What it proves to the verifier.** That the committed amount of one
VTXO satisfies a **public bound** without revealing the amount. The
default v1 form is one-sided: `committed_amount ∈ [0, max)`. A
two-sided variant proves `committed_amount ∈ [min, max]`. The
construction wraps the existing Back-Maxwell range proof (see
[ADR-0001](../adr/0001-secp256k1-zkp-integration.md) §FU-BP for the
underlying primitive); `BoundedRange` adds an integer comparison that
binds the verified range to the caller-supplied bound.

**What the verifier learns.**

- That the named VTXO's amount is below `max` (or in `[min, max]`).
- The exact bound (`max`, signed).
- Nothing more.

**What the verifier does *not* learn.**

- The actual amount.
- The blinding factor.
- Anything about other VTXOs, even those in the same round.

**Canonical institutional use case.** **FATF Travel Rule threshold**
attestations. Most jurisdictions implementing the Travel Rule
(EU under MiCA Article 75; the U.S. under the Bank Secrecy Act
implementing rules; Singapore MAS Notice PSN02; Switzerland FINMA
guidance) impose information-sharing obligations on virtual-asset
service providers (VASPs) when a transaction crosses a threshold
(USD 1000 / EUR 1000 in many regimes; lower in some). A `BoundedRange`
bundle for `max = $1000` lets a counterparty VASP verify "this
transaction is below the Travel Rule threshold" *without* learning the
user's actual amount — preserving the privacy guarantee of the
confidential layer for sub-threshold transactions.

**Cryptographic note.** Per the disclosure-types ADR §`BoundedRange`,
the bundle MUST carry the prover-intended `(min_bits, exp)` parameters
so the verifier reconstructs the *exact* range the prover meant. This
closes a gap where Back-Maxwell's auto-sized range can be wider than
the prover intended — without the parameters, a prover who picked a
generous bit-width could collide with the bundle's claimed `max`.

### 3.4 `SourceOfFunds` — AML provenance

**Status at CV-M6.** Wire-tag `0x0004` is **reserved**; the verifier
ships gated behind the `source-of-funds-proof` Cargo feature, which is
**default-off** at the CV-M6 ship gate. The feature flips to default-on
in a follow-up release once end-to-end tests have run on regtest for
at least one release cycle. Until that release, integrators reading
this guide should treat `SourceOfFunds` as available-on-request rather
than available-by-default.

**What it proves to the verifier.** That the named VTXO descends from
a declared ancestor VTXO via a chain of ≤ `max_depth` nullifier-linked
hops, signed by the holder of the spend key for each intermediate hop.
The chain shape is fully visible to the verifier; the **amounts at
intermediate hops are not** (per ADR §`SourceOfFunds` MUST NOT carry
intermediate-hop amounts).

**What the verifier learns.**

- That a chain `[ancestor → ... → target]` exists.
- The chain length.
- For each hop: the nullifier, the spent VTXO id, the produced VTXO id,
  and the round commitment in which the spend was settled.
- That the user controls the spend key at each hop (signed
  attestation).

**What the verifier does *not* learn.**

- The amount at any intermediate hop.
- The amounts at the ancestor or the target (those are separate
  disclosures, e.g. paired with a `VtxoReveal` for the target only).
- The wallet identities at any intermediate hop, beyond that the same
  spend key controlled all of them.

**Canonical institutional use case.** AML provenance: "Prove this
VTXO descends from a deposit at a licensed on-ramp." The user issues a
`SourceOfFunds` bundle whose `ancestor_vtxo_id` is the deposit VTXO
and whose `target_vtxo_id` is the VTXO they are now sending to a
counterparty. The counterparty's screening pipeline verifies the
chain.

**Limits and caveats.**

- **Chain length is bounded.** `max_depth ≤ 256` at the parser layer
  per ADR §`SourceOfFunds` MUST cap chain length. Bundles exceeding
  the bound are rejected as `InvalidEncoding` before any signature
  check.
- **Chain-shape leakage.** The verifier learns the shape of the chain.
  For users with rich payment graphs, the *shape* itself can be
  identifying; sophisticated users coordinate with their auditor on
  what level of detail is appropriate.
- **Cross-chain replay defence.** The signature transcript binds
  `network_genesis_round_id` so that a chain emitted on regtest
  cannot be replayed on mainnet (and vice versa).

### 3.5 Composing multiple disclosures

A single VTXO can be the subject of more than one disclosure. A common
combination:

1. `VtxoReveal` to disclose the amount.
2. `BoundedRange` to redundantly attest the amount is below a regulator's
   threshold (useful when the regulator's tooling consumes range
   proofs but not exact-amount reveals).
3. `SourceOfFunds` to prove provenance back to a clean source.

In v1, each disclosure is a **separate bundle** (per the
disclosure-types ADR §Composable inside one bundle requirement —
multi-proof envelopes are deferred as wire-tag `0x0007`). Verifiers
combine the three bundles in their own tooling; the operator-side
endpoint accepts each bundle independently and returns three
`VerificationResult` payloads.

---

## 4. Lifecycle: bundle generation, hand-off, verification

This section walks through what happens at each step of a disclosure,
from the moment the user decides to disclose to the moment the
verifier writes the result into their case file. The cryptographic
behaviour is deterministic and well-defined; the operational flow
around it is the part most regulators want documented.

### 4.1 Step-by-step lifecycle

```
Wallet                                        Auditor / Regulator / Counterparty
------                                        -----------------------------------

(1) Decide what to disclose.                                        
    ├─ Which VTXO(s)?                                               
    ├─ What scope? (epoch range, single VTXO, max-bound, ancestor)
    └─ Which audience? (single recipient, optional auditor-binding)

(2) Generate bundle.                                                
    ├─ ark-cli disclose viewing-key | reveal-vtxo |
    │  prove-range | prove-source                                   
    ├─ Wallet computes the proof (locally, no operator interaction).
    ├─ Wallet signs the canonical-encoded bundle with spend key.
    └─ Wallet emits a deterministic-CBOR file.                     

(3) Hand off out-of-band.   ────────────────────►   (3') Receive bundle.
    ├─ HTTPS upload, SFTP, signed email, USB.       ├─ Store as case-file evidence.
    └─ Out of operator's path.                       └─ Confirm receipt.

                                                  (4) Verify.
                                                   ├─ Option A: ark-cli verify-proof <path>
                                                   │            (verifier runs the maths
                                                   │             on their own laptop)
                                                   ├─ Option B: VerifyComplianceProof gRPC
                                                   │            against any honest dark node
                                                   └─ Both options run the same verifier code.

                                                  (5) Render verification result.
                                                   ├─ Structured fields (vtxo_id, amount or
                                                   │  range or chain shape, scope, timestamp).
                                                   └─ Bind into compliance workflow.
```

### 4.2 What the wallet does (steps 1–2)

The wallet — concretely, the user's `ark-cli` binary, but equivalently
any SDK that links the `dark-confidential::disclosure` module — does
all the cryptographic work locally. There is no operator round-trip
during bundle generation. Specifically:

- **Reads the user's spend secret key** from the local wallet store.
- **Reads the public on-chain round commitments** the bundle will
  reference (these are pulled from any dark node, the operator's or a
  third party's; they are not secret).
- **Computes the proof** appropriate to the bundle type (a Pedersen
  opening for `VtxoReveal`, a scope-tweaked scalar for
  `ViewingKeyIssuance`, a Back-Maxwell range proof plus bound for
  `BoundedRange`, a chain of per-hop nullifier derivations for
  `SourceOfFunds`).
- **Canonically encodes the payload** as deterministic CBOR per
  RFC 8949 §4.2.1 (sorted map keys, shortest-form integers,
  definite-length strings) per
  [`docs/adr/m6-dd-compliance-bundle-format.md` §Decision](../adr/m6-dd-compliance-bundle-format.md).
- **Signs the canonical bytes** with the user's spend key using BIP-340
  Schnorr over secp256k1, with a domain-separation tag specific to the
  proof type (e.g. `dark-confidential/disclosure/vtxo-reveal/v1`).
- **Optionally embeds an `auditor_binding`** — the auditor's long-lived
  Schnorr public key — so a corrupt auditor cannot replay the bundle
  to a third party who trusts the same wallet but a different auditor.
- **Writes the bundle** as a single `.bundle` file (binary CBOR) or
  prints it as base64 with `--json --base64` for transport over
  text-only channels.

The wallet logs the issuance locally (timestamp, bundle hash, scope,
recipient if known) so the user has their own audit trail of what they
have disclosed to whom.

### 4.3 What the verifier does (steps 4–5)

The verifier — concretely, the auditor's tooling — performs **only
public computations**:

- **Parses** the deterministic-CBOR envelope.
- **Verifies the issuer signature** by recomputing the canonical
  signed pre-image and running BIP-340 Schnorr verification under the
  issuer's spend public key. The issuer's spend public key is recovered
  from the wallet's published meta-address (out-of-band; e.g. the
  issuer's website, the institution's regulatory filing, a registry).
- **Dispatches** on `proof_type` to the matching verifier:
  `0x0001 → ViewingKeyIssuance` verifier, `0x0002 → VtxoReveal`,
  `0x0003 → BoundedRange`, `0x0004 → SourceOfFunds`.
- **Runs the proof-type-specific verifier** against the public
  on-chain commitments (recomputes a Pedersen commitment, runs a
  range-proof verifier, walks a graph against the round-tree, etc.).
- **Returns a structured result** (accept / reject) plus the
  proof-type-specific fields the human auditor renders into their
  case file (the disclosed `vtxo_id`, the verified amount or range,
  the chain shape).

The verifier never needs to contact the operator on the verification
path. They MAY use the operator's `VerifyComplianceProof` gRPC
endpoint ([§8](#8-verifycomplianceproof-grpc-endpoint)) as a
convenience, but it is just an unauthenticated stateless service that
runs the same maths and returns the same answer; it is not in the
trust path.

### 4.4 What does *not* happen during a disclosure

Stating these explicitly because their absence is load-bearing:

- **The operator is never queried during bundle generation.** A wallet
  offline from the operator's gRPC service can still emit any bundle.
- **The operator is never queried on the verification path.** A
  verifier with the bundle plus a public mirror of the round
  commitments can verify offline.
- **No new on-chain artefact is published.** Issuing a bundle does not
  consume bandwidth on the operator's round schedule, does not require
  a transaction, and does not change the on-chain state.
- **The user's published meta-address does not change.** Issuing a
  bundle does not require the user to rotate their meta-address; the
  meta-address is unchanged before and after.
- **No third-party trust is introduced.** A bundle's verification
  trusts (a) the wallet's spend key (signs the bundle), (b) the
  cryptographic primitives audited in the workspace
  ([ADR-0001](../adr/0001-secp256k1-zkp-integration.md)), and (c) the
  public on-chain round commitments. There is no "trusted setup",
  no "compliance oracle", no externally-signed list.

---

## 5. Regulatory framings: Travel Rule, MiCA, GENIUS Act

This section names the disclosure type that fits each major regulatory
regime and explains why. The mapping is **indicative**, not legal
advice. Each institution must obtain its own qualified legal opinion
on whether the disclosure types described here satisfy its specific
obligations under its specific competent authority.

### 5.1 FATF Travel Rule (Recommendation 16)

**The obligation.** Virtual-asset service providers (VASPs) must
collect and transmit originator and beneficiary information for
transactions above a jurisdictionally-defined threshold (commonly
USD 1000 / EUR 1000 / SGD 1500). For sub-threshold transactions the
obligation collapses to a record-keeping duty without sender-receiver
information transmission.

**The disclosure type that fits.** **`BoundedRange`** ([§3.3](#33-boundedrange--travel-rule-threshold-attestation)).

**Why.** The Travel Rule's threshold structure rewards precisely the
property `BoundedRange` provides: prove the amount is below the
threshold without revealing the amount. A user transferring funds
through a VASP that has implemented Travel Rule controls can submit a
`BoundedRange` bundle for `max = $1000` (or the local currency
equivalent at the scheme's published exchange rate). The VASP's
screening pipeline records "below threshold per cryptographic proof;
threshold-information-collection not required" as the audit-trail
entry, and the user's actual amount remains private.

**For sums above the threshold**, `BoundedRange` is *not* the
appropriate primitive — by construction it cannot prove "above
threshold". For above-threshold transfers, the institution typically
combines:

- **`VtxoReveal`** to disclose the exact amount to the regulated
  counterparty, and
- An **out-of-band Travel Rule message** carrying the originator and
  beneficiary information per the regime's wire format
  (IVMS101 / TRP / TR-IND).

The combination of `VtxoReveal` (cryptographically-binding amount
disclosure) + IVMS101 (off-chain originator / beneficiary information)
matches the Travel Rule's two-pronged structure.

**`SourceOfFunds`** is the corresponding primitive for the
**deposit-screening** side: a VASP receiving a deposit from an Ark
wallet may require the depositor to issue a `SourceOfFunds` bundle
proving the funds descend from a clean ancestor (the depositor's
verified on-ramp deposit).

### 5.2 EU Markets in Crypto-Assets Regulation (MiCA)

**The obligations** (this guide names obligations whose disclosure
shape matches one of v1's primitives; it is not a comprehensive MiCA
mapping):

- **Article 75** (CASP authorisation, transactional reporting): a CASP
  must report to its NCA on transactions executed on behalf of clients,
  with appropriate detail.
- **Title III–IV** (asset-referenced tokens, e-money tokens): the
  issuer must demonstrate that outstanding tokens are fully backed by
  a reserve.
- **Article 88** (insider lists / manipulation): regulated venues must
  retain records sufficient to detect manipulation.

**The disclosure types that fit.**

- **`ViewingKeyIssuance`** for **periodic NCA-facing reporting**. A
  CASP issues a viewing key scoped to the reporting period (e.g. a
  quarter, expressed as the corresponding epoch range) to the NCA's
  inspection team; the NCA's tooling decrypts every in-scope memo and
  reconciles against the institution's books. The viewing key is
  read-only; the CASP retains spend authority. The scope expires at
  the end of the reporting period (the auditor's tooling cannot
  decrypt VTXOs in a later period because no `scoped_scan_sk_E` for
  those epochs is in the bundle).
- **`VtxoReveal` aggregated** for **proof-of-reserves** (MiCA
  Title III–IV). An e-money-token issuer holding a reserve in
  confidential VTXOs can periodically issue a set of `VtxoReveal`
  bundles for every reserve VTXO; the NCA verifies each bundle, sums
  the disclosed amounts, and reconciles against outstanding tokens.
  The native primitive for this is `AggregateBalanceThreshold`
  (wire-tag `0x0005`, deferred — see ADR §Open Questions
  [FU-DT-AGG-BALANCE]); until that ships, the practical workaround is
  N parallel `VtxoReveal` bundles. Implementations that want to avoid
  per-VTXO disclosure for MiCA reserve attestation should track
  [FU-DT-AGG-BALANCE] and the underlying issue.
- **`BoundedRange`** for **per-transaction threshold reporting**. Where
  MiCA implementing acts mirror the FATF Travel Rule structure (Article
  75 read together with the Travel Rule transposition in Regulation
  (EU) 2023/1113), `BoundedRange` plays the same role as in
  [§5.1](#51-fatf-travel-rule-recommendation-16).
- **`SourceOfFunds`** for **AML provenance**. MiCA's AML/CFT framework
  refers through to the EU's Anti-Money Laundering Directives (AMLD5,
  AMLD6, and the forthcoming AMLA). Source-of-funds disclosure is the
  standard primitive for proving the origin of funds against a
  regulated on-ramp.

### 5.3 U.S. GENIUS Act (Guiding and Establishing National Innovation for U.S. Stablecoins)

**The obligations** (the Act creates a federal stablecoin regime that
imposes reserve-disclosure, reporting, and AML obligations on
permitted payment-stablecoin issuers; specific disclosure shapes
mirror the regulators' established practice):

- **§4 reserve disclosure**: issuers publish monthly attestations of
  reserve composition.
- **§5 BSA AML obligations**: issuers are subject to the Bank Secrecy
  Act, including SAR / CTR thresholds and Travel Rule transmission.
- **§6 examination rights**: the primary federal payment-stablecoin
  regulator (PFPSR) has supervisory examination powers.

**The disclosure types that fit.**

- **`VtxoReveal` aggregated** for **§4 monthly reserve attestations**.
  An issuer holding reserve VTXOs publishes a set of bundles whose
  aggregate amount equals the published reserve total. As above, the
  native primitive is `AggregateBalanceThreshold` (deferred).
- **`ViewingKeyIssuance`** for **§6 PFPSR examinations**. The issuer
  issues a viewing key scoped to the examination window to the PFPSR's
  examination team. The examination team decrypts every in-scope memo
  and reconciles. Outside the examination window, the viewing key
  cannot decrypt; the issuer's privacy guarantees for routine
  operations are preserved.
- **`BoundedRange`** for **§5 BSA SAR/CTR threshold compliance**. The
  Currency Transaction Report threshold (currently $10,000) maps
  directly onto a `BoundedRange` bound. The Suspicious Activity Report
  threshold is structurally similar.
- **`SourceOfFunds`** for **§5 BSA AML provenance**. Same role as
  under MiCA / FATF.

### 5.4 Cross-cutting note: viewing-key forwardability

All three regimes assume that the auditor / examiner / regulator will
**not** forward the disclosure beyond the institutional boundary. The
viewing-key forwardability caveat in [§3.1](#31-viewingkeyissuance--auditor-read-access-for-a-fixed-scope)
applies equally under each regime: a forwarded viewing key is a leaked
viewing key, and the user's recovery path (rotating the master
meta-address) is the same regardless of which regulatory regime
sourced the original disclosure. Institutions handing viewing keys to
regulators should obtain written attestation of the regulator's
key-handling policy *before* issuance.

---

## 6. Threat model and limits of disclosure

This section enumerates what is **not** guaranteed, so an integrator
or regulator can calibrate expectations correctly.

### 6.1 What a compromised viewing key discloses

A `ViewingKey` bundle is a list of per-epoch scoped scalars (one
secp256k1 scalar per epoch in scope) plus the issuance metadata, signed
by the user's spend key. If the bundle leaks:

- **An attacker decrypts every confidential memo addressed to the
  user's meta-address inside the issued epoch range.** This is the
  intended capability of a viewing key; the leak collapses the
  "voluntarily-issued to one auditor" property to "available to anyone
  who has the bundle".
- **An attacker recovers the user's master `scan_sk`.** Per
  [`docs/adr/m6-dd-viewing-key-scope.md` §Cross-cutting threat: collusion across two leaks](../adr/m6-dd-viewing-key-scope.md),
  the additive-tweak construction lets anyone with a single leaked
  scoped scalar plus the (publicly-derivable) tweak input recover
  `scan_sk = scoped_scan_sk_E - t_E (mod n)`. Once `scan_sk` is
  recovered, the attacker can decrypt every confidential memo ever
  addressed to the user's meta-address — past, present, and future —
  until the user rotates the meta-address. **This is a property of the
  v1 design**, documented openly so institutions can calibrate their
  key-handling discipline accordingly.
- **An attacker does *not* gain spend authority.** The viewing key is
  scan-only by construction; it cannot sign a spend.
- **An attacker does *not* gain authority over other wallets.** The
  bundle is specific to one wallet's meta-address.

The mitigation hierarchy is operational:

1. **Treat the bundle as catastrophic-loss-on-leak.** The CLI prints
   a prominent warning at issuance time per ADR §Mitigation
   (mandatory). Institutions should require an explicit risk
   acknowledgement before any viewing-key issuance.
2. **Bind to a specific auditor.** Issuance flows SHOULD populate the
   bundle's `auditor_binding` field so a forwarded bundle cannot be
   replayed against a different auditor's tooling. The signature
   covers the binding; tampering invalidates the bundle.
3. **Scope as narrowly as the audit allows.** A viewing key for "one
   week" is materially safer than a viewing key for "one year"
   *operationally* (smaller window of incoming activity in-scope at
   any moment) even though the cryptographic blast radius
   (master `scan_sk` recovery) is the same in both cases.
4. **Rotate on suspicion.** If a viewing key is suspected to have
   leaked, rotate the master meta-address immediately. The recovery
   path is documented in [§3.1](#31-viewingkeyissuance--auditor-read-access-for-a-fixed-scope).

### 6.2 Scope mechanism — epoch bucketing

The viewing key is bounded by **epoch range**, where one epoch is a
fixed-width window of rounds (default `EPOCH_SIZE_ROUNDS = 1024`,
≈ 17 hours at a 60-rounds-per-hour deployment). Per
[`docs/adr/m6-dd-viewing-key-scope.md` §Numerical bounds](../adr/m6-dd-viewing-key-scope.md):

- **`MIN_SCOPE_EPOCHS = 1`**. Issuing a viewing key for less than one
  epoch is forbidden; per-VTXO disclosure (issued via `VtxoReveal`) is
  the appropriate primitive.
- **`MAX_SCOPE_EPOCHS = 8192`**. Issuing a viewing key for more than
  8192 epochs is forbidden; users who want longer audit coverage issue
  multiple bundles. The bound prevents accidental "view forever"
  issuance.
- **Operator-tunable epoch size**. Deployments can retune
  `EPOCH_SIZE_ROUNDS` to match their round rate. A deployment with
  `EPOCH_SIZE_ROUNDS = 1024` at 60 r/h has 17-hour epochs; at 12 r/h
  the epoch is ≈ 85 hours. Deployments with non-default values MUST
  publish the value alongside the meta-address so counterparties can
  compute matching scoped pubkeys.

Auditors should expect viewing-key bundles to be sized in the kilobyte
range. A 90-day audit at default config is ≈ 4 KB; a year-long audit
is ≈ 16 KB. An auditor receiving a bundle materially larger than this
(e.g. multi-megabyte) should treat it as suspicious — the scope is
either implausibly long or the bundle has been manipulated.

### 6.3 What a compromised `VtxoReveal` discloses

A leaked `VtxoReveal` bundle reveals the named VTXO's amount to anyone
who obtains it. It does **not** reveal:

- Anything about other VTXOs.
- The user's spend authority (the bundle is signed but does not
  authorise a spend).
- Anything about the user's broader graph.

Mitigation: same as any other amount-disclosure document — treat it
as commercially sensitive but not catastrophic-loss-on-leak.

### 6.4 What a compromised `BoundedRange` discloses

A leaked `BoundedRange` bundle reveals "VTXO V's amount is below
`max`" to anyone who obtains it. The user's actual amount remains
hidden; the bundle is unforgeable but its informational content was
already public-by-construction once the user issued it.

Mitigation: treat as low-sensitivity (the bundle does not unlock any
private information beyond what the user explicitly disclosed).

### 6.5 What a compromised `SourceOfFunds` discloses

A leaked `SourceOfFunds` bundle reveals the chain shape to anyone who
obtains it. As noted in [§3.4](#34-sourceoffunds-amlprovenance), the
chain shape can be identifying for users with rich payment graphs.
Amounts at intermediate hops are not revealed.

Mitigation: scope the bundle's audience deliberately. `auditor_binding`
([§4.2](#42-what-the-wallet-does-steps-12)) prevents a corrupt
auditor from replaying the bundle to a different auditor's tooling
without re-signing.

### 6.6 Replay defence

Every bundle carries `(issuance_timestamp, nonce)` in its signed
header and a `network_genesis_round_id` in its signed payload (the
last bound at the verifier layer to prevent cross-chain replay). A
verifier MAY enforce a freshness window (the v1 default is
*disabled* — freshness is the auditor's policy, not a protocol
requirement), in which case bundles older than the window are
rejected with `BundleFreshnessError`.

### 6.7 What is *not* a threat the system mitigates

Stating these so an integrator does not falsely assume coverage:

- **The user's spend key is compromised.** If an attacker recovers
  the user's spend key, they hold every property the user holds: they
  can spend, sign new disclosure bundles, and rotate the
  meta-address. This is outside the scope of selective disclosure — it
  is the wallet-security threat addressed by hardware wallets, MPC
  custody, and the user's own operational hygiene.
- **Out-of-band key-handling failures.** If the user emails the
  viewing key in plaintext to the wrong auditor, the protocol
  cannot help. The bundle is opaque bytes on the wire; the user is
  responsible for wire confidentiality.
- **Adversarial counterparty inferring metadata from timing or
  amounts.** A counterparty that receives a `BoundedRange` bundle and
  reasons "this counterparty disclosed they are below $1000, therefore
  they probably hold around $X based on prior transaction rates" is
  performing inference outside the cryptographic boundary. The
  protocol does not, and cannot, mitigate inference attacks beyond the
  immediate informational content of each disclosure.

---

## 7. Worked examples with `ark-cli`

The `ark-cli` binary ships disclosure subcommands per
[issue #568](https://github.com/lobbyclawy/dark/issues/568). This
section walks through end-to-end invocations for each shipping
disclosure type, including the verifier side. Each command is
documented with at least one example in `--help` (per the issue's
acceptance criterion).

The general shape:

```text
ark-cli disclose <subcommand> [args]   →   produces a .bundle file
ark-cli verify-proof <bundle_path>     →   reads a .bundle, verifies, prints result
```

All commands accept `--json` for scripted use and produce a
human-readable summary by default.

### 7.1 Issuing a viewing key for a quarterly NCA audit

**Scenario.** A regulated CASP needs to issue a viewing key to its
NCA's inspection team covering the period 2026-07-01 → 2026-09-30
(Q3 2026). The CASP's deployment uses the default
`EPOCH_SIZE_ROUNDS = 1024`. The corresponding round-id range is
published by the operator's wall-clock-to-round-height index (an
advisory artefact published by every dark deployment).

**Step 1 — Translate calendar dates to round IDs.** Using the
deployment's published index (or `ark-cli wallet round-at-time
2026-07-01T00:00:00Z`):

```text
2026-07-01T00:00:00Z → round_height 132480
2026-09-30T23:59:59Z → round_height 264959
```

**Step 2 — Translate round IDs to epoch IDs.**

```text
start_epoch = 132480 / 1024 = 129
end_epoch   = 264959 / 1024 = 258
```

**Step 3 — Issue the viewing key.**

```bash
ark-cli disclose viewing-key \
    --scope rounds:132480..264959 \
    --auditor-binding-pubkey <NCA_INSPECTOR_XONLY_PUBKEY_HEX> \
    --output ./Q3-2026-NCA-audit.bundle \
    --i-understand-viewing-key-risk
```

The `--i-understand-viewing-key-risk` flag is required (per the
ADR's mandatory mitigation) for non-interactive use. In an interactive
session, omitting the flag triggers a confirmation prompt with the
warning *"This bundle reveals every VTXO ever paid to your
meta-address if it leaks. Treat it as you would your wallet seed for
the scope's lifetime."*

**Output.**

```text
Bundle written to ./Q3-2026-NCA-audit.bundle  (size: 4126 bytes)
proof_type:        ViewingKeyIssuance (0x0001)
issuer_pk:         <pubkey hex>
scope:             epochs 129..=258 (≈ Q3 2026)
auditor_binding:   <NCA_INSPECTOR_XONLY_PUBKEY_HEX>
issuance_ts:       2026-10-04T08:30:00Z
nonce:             <32 bytes hex>

WARNING: this bundle decrypts every confidential memo paid to your
meta-address inside the scope. If it leaks, the leak is recoverable
to your master scan key. Treat it as you would your wallet seed for
the scope's lifetime. Rotate the meta-address (`ark-cli wallet
rotate-meta-address`) if leak is suspected.
```

**Step 4 — Hand off out-of-band.** The CASP transmits
`Q3-2026-NCA-audit.bundle` to the NCA via a channel both parties
trust (signed email, SFTP into the NCA's portal, in-person USB key).
The transmission itself is out of scope for the protocol.

**Step 5 — NCA verifies.** The NCA's inspector runs:

```bash
ark-cli verify-proof ./Q3-2026-NCA-audit.bundle --json
```

```json
{
  "accepted": true,
  "proof_type": 1,
  "details": {
    "ViewingKeyIssuance": {
      "issuer_pubkey": "...",
      "scope": { "epoch_range": [129, 258] },
      "auditor_binding": "...",
      "epoch_count": 130,
      "spot_check_index": 47,
      "spot_check_passed": true,
      "issuance_ts": "2026-10-04T08:30:00Z"
    }
  }
}
```

**Step 6 — NCA decrypts in-scope memos.** The inspector's tooling
loads the viewing key and walks every memo addressed to the
issuer's meta-address inside epochs 129..=258. Decryption succeeds for
in-scope memos and yields `(vtxo_id, amount, blinding, memo_text)`.
Out-of-scope memos return `None` (cryptographic enforcement, not a
tooling filter).

### 7.2 Disclosing one VTXO to a counterparty

**Scenario.** An OTC desk closed trade T-2026-04-25-0042 by paying
0.42 BTC into the user's confidential VTXO `vtxo_id =
abc123…def456:0`. The user must prove receipt to the desk's middle
office.

**Step 1 — Issue the bundle.**

```bash
ark-cli disclose reveal-vtxo abc123...def456:0 \
    --output ./T-2026-04-25-0042-receipt.bundle
```

**Output.**

```text
Bundle written to ./T-2026-04-25-0042-receipt.bundle  (size: 312 bytes)
proof_type:    VtxoReveal (0x0002)
vtxo_id:       abc123...def456:0
amount:        42_000_000 sat (0.42 BTC)
blinding:      <32 bytes hex>
issuer_pk:     <pubkey hex>
issuance_ts:   2026-04-25T09:00:00Z
```

**Step 2 — Hand off.** Email or signed message to the OTC desk's
middle office.

**Step 3 — Middle office verifies.**

```bash
ark-cli verify-proof ./T-2026-04-25-0042-receipt.bundle
```

```text
ACCEPTED  VtxoReveal (0x0002)
  vtxo_id:        abc123...def456:0
  amount:         42_000_000 sat (0.42 BTC)
  commitment:     <commitment bytes hex>
  recomputed:     <recomputed bytes hex>  [byte-equal: yes]
  issuance_ts:    2026-04-25T09:00:00Z
  issuer_pk:      <pubkey hex>
```

The middle office's compliance system stores the bundle and the
verifier output as evidence; the trade is booked.

### 7.3 Travel-Rule threshold attestation

**Scenario.** A user is sending an Ark-confidential payment to a
counterparty VASP whose Travel Rule policy requires originator
information for transfers ≥ $1000 USD-equivalent. The user's amount
is below threshold, and they want to avoid disclosing the actual
figure.

**Step 1 — Compute the bound.** At the scheme's published
exchange rate, $1000 ≈ 1_500_000 sat. The user picks `max =
1_500_000` sat as the bound. (In practice the threshold is set
per-jurisdiction; the user's wallet UI surfaces the appropriate
default.)

**Step 2 — Issue the bundle.**

```bash
ark-cli disclose prove-range <vtxo_id> --max 1500000 \
    --output ./travel-rule-threshold.bundle
```

The CLI requires the `bounded-range-proof` Cargo feature (default-on
at the CV-M6 ship gate). On a build without the feature, the command
prints `error: feature 'bounded-range-proof' not enabled in this
build` and exits with status 2.

**Output.**

```text
Bundle written to ./travel-rule-threshold.bundle  (size: 814 bytes)
proof_type:    BoundedRange (0x0003)
vtxo_id:       <vtxo_id>
max:           1_500_000 sat
proof_size:    672 bytes
proving_time:  287 ms
issuer_pk:     <pubkey hex>
issuance_ts:   2026-04-25T09:30:00Z

NOTE: the verifier will learn that the amount is below 1_500_000 sat.
The exact amount is NOT disclosed.
```

**Step 3 — VASP verifies.**

```bash
ark-cli verify-proof ./travel-rule-threshold.bundle --json
```

```json
{
  "accepted": true,
  "proof_type": 3,
  "details": {
    "BoundedRange": {
      "vtxo_id": "...",
      "max": 1500000,
      "verified_range_inclusive": [0, 1499999],
      "issuer_pubkey": "...",
      "issuance_ts": "2026-04-25T09:30:00Z"
    }
  }
}
```

The VASP's screening pipeline records "Travel Rule sub-threshold per
cryptographic proof, originator-information collection not required"
and proceeds.

### 7.4 AML provenance via `SourceOfFunds`

**Status.** Wire-tag `0x0004` is reserved; the `source-of-funds-proof`
Cargo feature is **default-off** at the CV-M6 ship gate. The example
below is operational once the feature flips to default-on (or for
deployments that build with `--features source-of-funds-proof`
explicitly).

**Scenario.** A user is depositing into a regulated exchange. The
exchange's deposit-screening pipeline requires proof that the deposit
descends from a clean ancestor (the user's verified KYC'd on-ramp
deposit at Exchange Z three months earlier).

**Step 1 — Identify the ancestor.** The user's wallet UI surfaces
"VTXO from Exchange Z, dated 2026-01-15, vtxo_id `vyz789...:0`" as
the verified clean ancestor.

**Step 2 — Issue the bundle.**

```bash
ark-cli disclose prove-source <target_vtxo_id> \
    --back-to vyz789...:0 \
    --max-depth 16 \
    --output ./aml-provenance.bundle
```

**Output.**

```text
Bundle written to ./aml-provenance.bundle  (size: 4_812 bytes)
proof_type:      SourceOfFunds (0x0004)
target:          <target_vtxo_id>
ancestor:        vyz789...:0
chain_depth:     6 hops
issuer_pk:       <pubkey hex>
issuance_ts:     2026-04-25T10:00:00Z

NOTE: the verifier will learn the chain shape (6 hops, the nullifier
and VTXO id at each hop, and the round each hop settled in). The
verifier will NOT learn amounts at any intermediate hop.
```

**Step 3 — Exchange verifies.**

```bash
ark-cli verify-proof ./aml-provenance.bundle --json
```

```json
{
  "accepted": true,
  "proof_type": 4,
  "details": {
    "SourceOfFunds": {
      "target_vtxo_id": "...",
      "ancestor_vtxo_id": "vyz789...:0",
      "hops": 6,
      "issuer_pubkey": "...",
      "issuance_ts": "2026-04-25T10:00:00Z"
    }
  }
}
```

The exchange's AML pipeline checks `vyz789...:0` against the
"verified clean on-ramp deposits" allowlist; if present, the deposit
is accepted.

### 7.5 What happens on bad input

The CLI's verifier surfaces structured errors per the disclosure-types
ADR §`UnknownProofType` rule and the bundle-format ADR §Forward-compat
denial.

**Unknown proof type** (e.g. a v2 type the v1 binary does not
support):

```text
error: unknown proof type 0x0042; this CLI was built without support for it
exit status: 2
```

**Tampered bundle** (e.g. a single byte flipped):

```text
error: issuer signature verification failed
  proof_type:      VtxoReveal (0x0002)
  expected_issuer: <pubkey hex>
exit status: 1
```

**Wrong opening for a `VtxoReveal`:**

```text
error: commitment mismatch
  proof_type:        VtxoReveal (0x0002)
  vtxo_id:           <vtxo_id>
  expected:          <on-chain commitment hex>
  recomputed:        <recomputed commitment hex>
exit status: 1
```

**Out-of-scope viewing key** (the verifier is looking at a memo from
a round outside the bundle's epoch range):

```text
note: VTXO at round 132479 is below scope (start_epoch 129 starts at round 132096)
                                                                        ↑ in this case the round IS in scope; example is illustrative
```

The verifier's behaviour for actual out-of-scope memos is to return
`None` per [`docs/adr/m6-dd-viewing-key-scope.md` §Verifier-side enforcement](../adr/m6-dd-viewing-key-scope.md);
it does not raise an error, because "not in scope" is a normal
expected return value for any memo the auditor encounters.

---

## 8. `VerifyComplianceProof` gRPC endpoint

The dark operator runs a gRPC service whose schema includes a
`VerifyComplianceProof` method, defined in
[issue #569](https://github.com/lobbyclawy/dark/issues/569) and pinned
by the disclosure-types ADR §#569 (`VerifyComplianceProof` gRPC endpoint) MUST.

The endpoint is a **convenience for verifiers**: it does the same
maths as `ark-cli verify-proof` but as a gRPC call, so a verifier
without a local Rust toolchain can verify a bundle by sending it to
any honest dark node.

### 8.1 Method signature

```text
service ComplianceService {
    rpc VerifyComplianceProof(ProofBundle) returns (VerificationResult);
}
```

The `ProofBundle` payload is the deterministic-CBOR bundle bytes,
unwrapped from any transport encoding. The `VerificationResult`
payload is a structured response:

```text
message VerificationResult {
    bool   accepted    = 1;     // verifier accept/reject
    uint32 proof_type  = 2;     // wire-tag echoed back
    oneof details {             // proof-type-specific structured fields
        ViewingKeyDetails    viewing_key    = 10;
        VtxoRevealDetails    vtxo_reveal    = 11;
        BoundedRangeDetails  bounded_range  = 12;
        SourceOfFundsDetails source_of_funds = 13;
    }
    string error_code  = 30;    // populated when accepted=false
    string error_message = 31;
}
```

The `details` oneof carries one arm per shipping wire-tag; each arm
contains the same structured fields the CLI prints in `--json` mode
(see [§7](#7-worked-examples-with-ark-cli)).

### 8.2 Operational properties

Per the disclosure-types ADR §#569 (`VerifyComplianceProof` gRPC endpoint) MUST:

- **Unauthenticated.** The bundle carries its own issuer signature;
  the operator does not need to authenticate the caller. Authentication
  would not improve security (the verifier could lie about who they
  are anyway) and would create operator-side data they shouldn't have.
- **Rate-limited.** Per IP/network, operator-policy-defined; mitigates
  the obvious DoS surface. Default rate is documented in the
  operator's runbook.
- **Stateless verification.** Each request is independent; the
  operator does not cache results. Replay-detection is the bundle's
  responsibility (issuance timestamp + signed nonce).
- **No secret material.** The verification path runs against public
  on-chain data only. The operator never holds, derives, or stores any
  per-bundle secret.

### 8.3 Audit logging

Per the ADR's observability acceptance criterion, the endpoint MUST
audit-log every verification request with
`(timestamp, caller_ip, proof_type, bundle_size_bytes, result)` —
**but it MUST NOT capture the bundle bytes**. Logging the bundle bytes
would re-introduce the operator-as-custodian property the protocol
avoids: viewing-key bundles in particular contain decryption-equivalent
secrets, and an operator log with bundle contents would be a deep-state
compromise vector.

The audit log is **structural**: which proof types are being
verified, at what rate, with what acceptance ratio. The log is **not**
informational about the underlying user activity.

### 8.4 Error semantics

The endpoint returns a typed error rather than crashing on:

- **Unknown / reserved-but-disabled tag.** Returns gRPC
  `INVALID_ARGUMENT` with `error_code = "UNKNOWN_PROOF_TYPE"` and
  `error_message` carrying the tag value (e.g. `"unknown proof type
  0x0005"`).
- **Malformed CBOR.** Returns gRPC `INVALID_ARGUMENT` with
  `error_code = "BUNDLE_PARSE_ERROR"`.
- **Bad signature.** Returns the standard `accepted = false` response
  with `error_code = "ISSUER_SIGNATURE_FAILED"` (this is *not* a
  protocol error; it is the verifier's normal "reject" response).
- **Unsupported version.** Returns gRPC `INVALID_ARGUMENT` with
  `error_code = "UNSUPPORTED_VERSION"`.

Verifiers should treat `accepted = false` as the authoritative
"reject"; they should treat `INVALID_ARGUMENT` errors as a request
they need to retry with a valid bundle (the bundle they sent was
malformed in some structural sense before signature verification could
even begin).

### 8.5 Operator does not learn auditor identity

A verifier calling `VerifyComplianceProof` need not identify
themselves; the endpoint is unauthenticated. The operator therefore
learns:

- That **someone** verified a bundle of a specific type at a specific
  time (audit-log entry).
- The bundle contents (during the verification call only; the bytes
  are not logged per §8.3).

The operator does **not** learn:

- The verifier's organisational identity.
- The verifier's relationship to the issuer (the bundle's
  `auditor_binding`, if present, is opaque from the operator's
  perspective; only an auditor whose pubkey matches can use the
  bundle, but the operator does not run that policy check).
- The user-facing outcome of the verification (e.g. whether the
  auditor accepted the trade, booked the deposit, or filed a SAR).

---

## 9. Explicit non-goals

This section enumerates properties the system **does not** commit to,
so an integrator or regulator cannot reasonably misunderstand. Each is
load-bearing.

### 9.1 Ark is not a KYC system

The Ark protocol's confidential VTXO layer holds no identity
information. There is no on-chain `KYC = true` flag, no per-user
"compliance status", no record of which jurisdictions a wallet operates
under. KYC is performed by integrating institutions (exchanges, custodians,
issuers) **off-chain**, against their own regulatory framework. The
disclosure primitives in this guide are tools for the user to *prove
facts* to a counterparty who has separately verified the user's
identity; they are not a substitute for KYC and do not provide
identity information by themselves.

### 9.2 Disclosure is user-initiated and voluntary

There is no coercion path inside the protocol. The user's spend key
is the trust root for every bundle; an institution cannot force the
user to issue a bundle via any operator-side channel. The institution
can, of course, *require* the user to issue a bundle as a condition
of service (e.g. "deposit acceptance is contingent on a
`SourceOfFunds` bundle"), but that is a contractual condition between
the institution and the user, not a protocol-level mechanism.

### 9.3 The operator has no back-door

Restated for emphasis: there is no key, anywhere in the system, that
the operator holds and that can decrypt amounts, recover identities,
or reconstruct the wallet graph. A regulator who serves a subpoena on
the operator obtains the operator's logs and the public on-chain data
the operator already publishes. Neither contains decrypted amounts or
identity information about Ark users.

### 9.4 Disclosure does not retroactively change confidentiality of *other* VTXOs

A user who issues a `VtxoReveal` for VTXO V on day D does not, by
that act, cause VTXO V' (a sibling, descendant, ancestor, or unrelated
VTXO) to become non-confidential. Each disclosure is bound to its
specific subject; the unlinkability properties of the underlying
nullifier scheme ([ADR-0002](../adr/0002-nullifier-derivation.md))
preserve confidentiality of every other VTXO. The exception is
`SourceOfFunds`, whose chain shape is intentionally revealed; even
there, only the chain *shape* is revealed, not the amounts.

### 9.5 Disclosure does not authorise spending

Every bundle is signed by the user's spend key, but the signature
authorises **disclosure**, not a spend. The signature transcript is
domain-separated per disclosure type
(`dark-confidential/disclosure/<type>/v1`) so that a disclosure
signature cannot be coerced into a spend authorisation by
re-interpretation. Per the disclosure-types ADR §#565 MUST NOT and
parallel constraints: every bundle is signed; no unauthenticated
disclosure mode exists; and the signature input is bound to the
disclosure's content, not to a spend.

### 9.6 Selective disclosure is not a substitute for off-chain
information sharing

The Travel Rule (§5.1) requires VASP-to-VASP information transmission
about originator and beneficiary. `BoundedRange` proves a threshold
property; it does **not** transmit the originator's name and address.
Above-threshold transfers require off-chain Travel Rule messages
(IVMS101 or equivalent) regardless of what bundles the user issues
on-chain. The cryptographic primitive complements the off-chain
process; it does not replace it.

### 9.7 The protocol does not warrant compliance with any specific regime

The mappings in [§5](#5-regulatory-framings-travel-rule-mica-genius-act)
are indicative and were authored as engineering documentation, not as
a legal opinion. Each integrating institution must obtain its own
qualified legal opinion on whether the disclosure types described
here satisfy its specific obligations under its specific competent
authority. Anthropic's role is the implementation; legal sufficiency
is the institution's role.

---

## 10. FAQ for auditors

### Q1. Can I trust a bundle I receive over email?

The bundle's signature binds it to the issuer's spend key; tampering
in transit is detectable. Confidentiality of the *transmission* is the
sender's responsibility (signed S/MIME, encrypted ZIP, or out-of-band
delivery). Once you have the bundle, the cryptographic verification
gives you the same guarantee whether you received it over TLS, SFTP,
or USB.

### Q2. Do I need to run my own dark node to verify?

No. You can verify with `ark-cli verify-proof <bundle_path>` against
your own laptop, no node required. The verifier needs (a) the bundle,
(b) the issuer's spend public key (recovered from the wallet's
published meta-address — published by the issuer out-of-band, e.g. on
their website or in their regulatory filing), and (c) the public
on-chain round commitments for the rounds the bundle references
(pulled from any honest mirror). Many auditors run their own dark
node anyway, for redundancy and to avoid trusting any single mirror.

### Q3. What's the difference between `VtxoReveal` and `ViewingKeyIssuance`?

`VtxoReveal` is a one-shot disclosure of one VTXO's amount.
`ViewingKeyIssuance` is a credential that lets you decrypt every memo
in a scope (potentially hundreds of VTXOs). Use `VtxoReveal` for
single-trade evidence; use `ViewingKeyIssuance` for periodic audits
covering a window of activity. The cryptographic blast radius of a
leaked `ViewingKeyIssuance` is *much larger* than that of a leaked
`VtxoReveal` — handle accordingly.

### Q4. Can a user issue *multiple* viewing keys to *different* auditors with overlapping scopes?

Yes. Each viewing key is cryptographically independent; leaking one
does not yield decryption authority for another, even if their scopes
overlap on some epochs. Per
[`docs/adr/m6-dd-viewing-key-scope.md` §Multiple scopes](../adr/m6-dd-viewing-key-scope.md):
overlapping scopes share the same scoped key for the overlapping
epochs (a single epoch has one scoped key), but the bundle handed to
each auditor is distinct, signed independently, and bound to its own
auditor.

### Q5. How long does verification take?

Per the disclosure-types ADR §Verifier-implementation requirements:
verification MUST run in seconds on a laptop. Concrete times:
`VtxoReveal` is microseconds (one Pedersen commitment + one Schnorr
verification); `ViewingKeyIssuance` is milliseconds for the
cryptographic checks plus linear-in-memos-walked time for the
decryption pass; `BoundedRange` is sub-second (Back-Maxwell range
proof verification); `SourceOfFunds` is ≈ 100 ms × chain length
(linear in hops, capped at 256). All four fit comfortably inside
"verifies during a single API call without holding a connection
open".

### Q6. What if the bundle's claimed scope conflicts with the on-chain commitments?

The verifier rejects the bundle. Per the bundle-format ADR §Standalone
verifiability: every cryptographic claim in the bundle is recomputed
against the public on-chain data; mismatches surface as typed
verification errors (`COMMITMENT_MISMATCH`, `NULLIFIER_NOT_PRESENT`,
`SCOPE_OUT_OF_RANGE`). A user cannot disclose a fact that contradicts
public on-chain state.

### Q7. Can the verifier tell if the bundle is *fresh*?

The bundle's signed header carries `issuance_timestamp` (UNIX seconds)
and a 32-byte `nonce`. Both are signed; replaying an old bundle is
detectable by its timestamp. The verifier MAY enforce a freshness
window (the v1 default is *disabled* — freshness is the auditor's
policy, not a protocol requirement). Auditors who require freshness
should configure their tooling's window explicitly.

### Q8. What about revocation?

There is no on-chain revocation primitive in v1. Revocation works
operationally:

- **`ViewingKeyIssuance`**: a viewing key is bounded by its scope;
  the auditor's authority expires at the end of the issued epoch
  range automatically. To revoke *before* the natural expiry, the
  user rotates their meta-address, which invalidates the auditor's
  ability to *receive* future payments under the old address (past
  payments inside the issued scope remain decryptable; this is a
  property of the construction, not a defect).
- **`VtxoReveal`, `BoundedRange`, `SourceOfFunds`**: these bundles
  attest a specific fact about a specific VTXO at a specific time.
  They are not credentials; they cannot be "revoked" in the sense
  of revoking a TLS certificate. The disclosed fact is permanent;
  the user's recourse if a bundle is misused is contractual (they
  control who receives the bundle, and rely on the recipient's
  data-handling discipline).

A future v2 may introduce on-chain revocation primitives if the
regulatory bar tightens; v1 does not.

### Q9. What's the audit trail on the wallet side?

The wallet logs every issued bundle locally (timestamp, bundle hash,
proof type, scope or subject VTXO, recipient if known). The user has
a full record of what they have disclosed. The log is local-only; the
operator does not see it, and other auditors do not see it.

### Q10. Can two auditors collude to recover information neither one individually has?

The cryptographic surface that admits collusion is the
viewing-key construction, where two leaked scoped scalars (or even
one) can be combined with public information to recover the master
`scan_sk` per [§6.1](#61-what-a-compromised-viewing-key-discloses).
Two auditors who hold viewing keys for non-overlapping scopes both
hold (distinct) scoped scalars. Either one alone — by the
single-leak threat model — already gives access to the master scan
key if leaked. Collusion does not strictly increase the attacker's
power beyond "either one of them leaks", but it does increase the
*surface* through which leak can happen. Mitigation: scope narrowly
and use the `auditor_binding` field to bind each bundle to one
specific auditor.

### Q11. What's a "scope binding hash" and why do I care?

The bundle header carries a 32-byte `scope_binding_hash` that pins the
bundle to a declared scope (round range, VTXO set, time window —
see [`docs/adr/m6-dd-compliance-bundle-format.md` §`scope_binding_hash`](../adr/m6-dd-compliance-bundle-format.md)).
The signature covers the hash, so a bundle's scope cannot be retroactively
re-interpreted. As a verifier you should always read the bundle's
declared scope, recompute the hash from your own copy of the scope
metadata, and confirm it matches what's signed; any mismatch is a
forgery attempt.

### Q12. Does using selective disclosure change my own data-handling
obligations under GDPR or equivalent?

A bundle that decrypts memos may surface personal data inside those
memos (e.g. a payment reference, a counterparty name). Once your
tooling has decrypted the data, your normal data-handling obligations
apply. The protocol does not minimise the data inside the memos; the
*user* writing the memo is the data minimisation gate. Auditors
receiving viewing keys should expect to handle the decrypted data
under their normal regime (storage encryption, access control,
retention policy) and should treat the bundle itself with the same
sensitivity classification.

---

## 11. References and cross-links

### CV-M6 ADRs (this guide is the operator/auditor companion)

- [`docs/adr/m6-dd-disclosure-types.md`](../adr/m6-dd-disclosure-types.md)
  — closes the v1 disclosure-type registry; pins which proofs ship
  and which are deferred behind feature flags.
- [`docs/adr/m6-dd-compliance-bundle-format.md`](../adr/m6-dd-compliance-bundle-format.md)
  — pins the deterministic-CBOR wire format, the canonical signing
  pre-image, and the unknown-proof-type handling rules.
- [`docs/adr/m6-dd-viewing-key-scope.md`](../adr/m6-dd-viewing-key-scope.md)
  — pins the epoch-bucketing scope mechanism, the numerical bounds
  on scope size, and the cross-cutting threat model around
  viewing-key leakage.

### Underlying primitive ADRs

- [`docs/adr/0001-secp256k1-zkp-integration.md`](../adr/0001-secp256k1-zkp-integration.md)
  — the secp256k1-zkp integration and the Back-Maxwell range-proof
  construction underlying `BoundedRange`.
- [`docs/adr/0002-nullifier-derivation.md`](../adr/0002-nullifier-derivation.md)
  — the nullifier scheme that creates the linkable graph
  `SourceOfFunds` traverses.
- [`docs/adr/0003-confidential-memo-format.md`](../adr/0003-confidential-memo-format.md)
  — the confidential memo encryption scheme that `ViewingKeyIssuance`
  decrypts.

### Related issues

- [Issue #561](https://github.com/lobbyclawy/dark/issues/561) — Viewing-key scope mechanism (closed; landed as the M6-DD viewing-key-scope ADR).
- [Issue #562](https://github.com/lobbyclawy/dark/issues/562) — Compliance proof bundle format (closed; landed as the M6-DD compliance-bundle-format ADR).
- [Issue #563](https://github.com/lobbyclawy/dark/issues/563) — Disclosure proof types shipping at launch (closed; landed as the M6-DD disclosure-types ADR).
- [Issue #564](https://github.com/lobbyclawy/dark/issues/564) — Viewing-key derivation, issuance, and verification (consumer of wire-tag `0x0001`).
- [Issue #565](https://github.com/lobbyclawy/dark/issues/565) — VTXO selective reveal with commitment opening (consumer of wire-tag `0x0002`).
- [Issue #566](https://github.com/lobbyclawy/dark/issues/566) — Bounded-range compliance proofs (consumer of wire-tag `0x0003`).
- [Issue #567](https://github.com/lobbyclawy/dark/issues/567) — Source-of-funds proofs over the linkable graph (consumer of wire-tag `0x0004`).
- [Issue #568](https://github.com/lobbyclawy/dark/issues/568) — `ark-cli` disclose / verify commands.
- [Issue #569](https://github.com/lobbyclawy/dark/issues/569) — `VerifyComplianceProof` gRPC endpoint.
- [Issue #570](https://github.com/lobbyclawy/dark/issues/570) — This compliance guide.

### Source code

- `crates/dark-confidential/src/disclosure/` — the v1 verifier
  functions for each shipping wire-tag.
- `crates/dark-confidential/src/commitment.rs` — Pedersen commitment
  construction consumed by `VtxoReveal` and `BoundedRange`.
- `crates/dark-confidential/src/range_proof.rs` —
  `verify_range_bounded` consumed by `BoundedRange`.
- `crates/dark-confidential/src/nullifier.rs` — nullifier derivation
  consumed by `SourceOfFunds`.
- `crates/ark-cli/` — `disclose` and `verify-proof` subcommands.
- `crates/dark-api/` — `VerifyComplianceProof` gRPC handler.

### Companion documentation

- [`docs/compliance-source-proofs.md`](../compliance-source-proofs.md)
  — earlier scaffolding for source-of-funds proofs in `dark-core`;
  `SourceOfFunds` (wire-tag `0x0004`) is the full nullifier-graph
  successor.

### External standards

- **RFC 8949** — Concise Binary Object Representation (CBOR), used as
  the wire format for compliance bundles.
- **BIP-340** — Schnorr Signatures for secp256k1, used for issuer
  signatures.
- **FATF Recommendation 16** — Travel Rule for virtual-asset
  service providers.
- **Regulation (EU) 2023/1114** — Markets in Crypto-Assets (MiCA).
- **U.S. GENIUS Act** — Guiding and Establishing National Innovation
  for U.S. Stablecoins.
- **IVMS101** — InterVASP Messaging Standard, used for off-chain
  Travel Rule message transmission.

---

*This document is reviewed by a compliance subject-matter expert per
the acceptance criterion of [issue #570](https://github.com/lobbyclawy/dark/issues/570).
The reviewer is named in the pull request that lands this file.*
