# ADR M6-DD: Viewing key scope mechanism (round / epoch bounds)

- **Status:** Proposed
- **Date:** 2026-04-25
- **Milestone:** CV-M6 (Selective Disclosure & Compliance)
- **Drives:** #561 → unblocks #564 → constrains #565, #568, #569, #570
- **Affects:** the encryption recipient slot of the confidential memo
  (ADR-0003) and the disclosure surface in `dark-confidential::disclosure`.
  Transparent paths and the confidential VTXO leaf script (ADR-0005) are
  untouched (#520 parity gate).
- **Companion ADRs:** ADR-0003 (memo format — pins the recipient pubkey
  the sender ECDH's against; this ADR substitutes a *scoped* scan pubkey
  for the master), ADR M5-DD stealth derivation (defines `scan_sk` /
  `scan_pk` and the BIP-32 path layout this ADR's tweak hangs off).

## Context

Confidential VTXOs hide both amount (Pedersen-committed) and recipient
(stealth-addressed). The operator cannot tell a user's incoming-payment
graph from the on-chain commitments alone — that information lives in
the AEAD-encrypted memo (ADR-0003) which only the holder of the
recipient's `scan_sk` can decrypt.

Milestone CV-M6 makes confidentiality *selectively reversible*. A user
voluntarily proves specific facts about specific VTXOs — "this output
paid me", "the amount was below threshold X", "this VTXO descends from
a compliant on-ramp" — without unmasking the rest of their wallet. The
target audience is institutional users who must satisfy regulatory
audit obligations (MiCA, FATF Travel Rule, GENIUS Act-style
disclosures, internal counterparty due diligence) **without** giving
their auditor a global view of every payment they have ever received.

Among the disclosure primitives shipping in M6 (per the
selective-disclosure scope: VTXO reveal, bounded-range proof,
source-of-funds proof, viewing key issuance), the **viewing key** is
the only one that grants the recipient ongoing, post-hoc decryption
authority — every other primitive is a one-shot signed assertion about
a single VTXO. A viewing key is therefore the most powerful
disclosure primitive and the one whose scope semantics are most
load-bearing.

The naive viewing-key construction is to hand the auditor the user's
master `scan_sk`. That scan_sk decrypts every confidential memo ever
addressed to the user's meta-address (#553) — past, present, and
future, until the user rotates their meta-address (which costs them
their published identifier and re-key every counterparty). This is
incompatible with the institutional reality where:

- An audit covers a **specific period** ("Q3 2026", "the last 90
  days", "rounds 100–200"), not the user's entire history.
- A regulated counterparty wants visibility into a **specific
  business relationship** ("payments tagged for this trading desk")
  without learning about the user's personal activity.
- The auditor's key MUST eventually expire. A "view forever" key is
  not a key, it is a permanent loss of confidentiality. If the
  auditor leaks the key — through subpoena, breach, or rogue
  insider — the leak's blast radius MUST be the audit period only,
  not the user's lifetime payment graph.
- The user MUST be able to issue **multiple** disjoint viewing keys
  (different auditors, different scopes, different expiries) without
  cross-pollination: leaking one auditor's key MUST NOT yield
  decryption authority for any other auditor's scope.

The mechanism that decides "which subset" is the **scope mechanism**,
and the choice has direct cryptographic consequences. There are two
broad families:

- **Hard scope** — the cryptographic key the auditor receives only
  succeeds against ciphertexts inside the scope. Out-of-scope
  ciphertexts cannot be decrypted with the audited key, *full stop*
  — no trust in the verifier's tooling, no risk that a buggy or
  malicious auditor "accidentally" decrypts more.
- **Soft scope** — the auditor receives the master `scan_sk` (or an
  equivalently-powerful key) and the audit tooling is *configured*
  to ignore VTXOs outside the declared scope. The scope is a CLI
  filter, not a mathematical bound. A motivated auditor (or an
  adversary that compromises the auditor's machine) can flip a
  config flag and recover everything.

The issue (#561) asks us to pick one and to specify the epoch
granularity, the wire encoding, and the recipient-UX impact. The
decision drives:

- ADR-0003's recipient-slot encoding — does the sender encrypt to
  the master `scan_pk`, or to a scope-derived `scoped_scan_pk` ?
- #564 (`ViewingKey` derivation, issuance, and verification) — what
  is the byte layout of a `ViewingKey`, and what is the API
  signature of `issue_viewing_key(spend_sk, scope) -> ViewingKey` ?
- #568 / #569 (`ark-cli` disclose, gRPC verify) — what does the user
  type to issue an auditor key, and what does the auditor receive?
- #565 / #566 / #567 (other disclosure primitives) — does the
  scoping mechanism interact with VTXO reveal, range proofs,
  source-of-funds proofs, or are those orthogonal?

This ADR fixes the scope construction, pins the epoch granularity,
specifies the cryptographic enforcement and the recipient/sender UX,
documents the threat model and the recovery procedure on auditor-key
leak, and constrains downstream issues to a single source of truth.

## Requirements

- **Cryptographic enforcement, not tooling enforcement.** The
  viewing key MUST succeed cryptographically against in-scope
  ciphertexts and MUST fail cryptographically against out-of-scope
  ciphertexts. "Fail" means the AEAD tag does not verify — the
  auditor's program returns `None`, not "I chose to ignore this
  result".
- **Bounded blast radius on key leak.** A leaked viewing key MUST
  reveal at most the scope it was issued for. Specifically: leaking
  a viewing key for scope `[E_a, E_b]` MUST NOT yield any
  information about VTXOs outside `[E_a, E_b]`, MUST NOT yield
  spending authority for any VTXO (not even in-scope ones), and
  MUST NOT yield any other viewing key the user has issued.
- **No new public publishing.** The user's published identifier
  remains the single meta-address from #553. Issuing a viewing key
  MUST NOT require the user to publish a new on-chain artefact, a
  new gRPC announcement, or any out-of-band registration with the
  operator. The viewing key is purely a private artefact handed
  off-band to the auditor.
- **Sender-side determinism.** The sender, holding the recipient's
  meta-address, MUST be able to compute the scoped recipient pubkey
  for the current scope from public information alone (round id /
  scope identifier) plus the recipient's published `scan_pk`. The
  sender MUST NOT need to know in advance which scope an auditor
  will eventually receive, MUST NOT need to participate in any
  per-output ceremony with the recipient, and MUST NOT need to
  encrypt the same memo twice (no "encrypt once for the user, once
  for the auditor").
- **Recipient-side reconstruction.** The recipient, holding their
  master `scan_sk` plus the public scope identifier of an
  announced VTXO, MUST be able to derive the scoped `scoped_scan_sk`
  that decrypts the memo. The derivation MUST be a constant-time
  arithmetic operation, not a per-VTXO ECDH (the ECDH still
  happens — it always does, by ADR-0003 — but the *scoping
  derivation* is one tagged-hash plus one scalar add).
- **Spending authority preserved.** The recipient retains spending
  authority for in-scope and out-of-scope VTXOs alike via their
  master `spend_sk`. The viewing key MUST NOT involve the spend
  key, MUST NOT change the one-time-key derivation in #554, and
  MUST NOT touch the unilateral-exit script in ADR-0005.
- **Time-bounded scopes via the same primitive.** The mechanism
  that supports "rounds 100–200" MUST also support "Q3 2026"
  without a second, parallel construction. A user who thinks in
  calendar time and an auditor who thinks in round ids see the
  same artefact under the hood.
- **Multiple concurrent scopes.** A user MUST be able to issue
  several viewing keys simultaneously (Auditor A: rounds 100–200;
  Auditor B: rounds 150–250; counterparty C: rounds 200–210) and
  the keys MUST be cryptographically independent — leaking A
  reveals nothing about B or C, including for the rounds where
  their scopes overlap.
- **Forward-compatibility with #564's issuance API.** The `ViewingKey`
  type returned by `issue_viewing_key(spend_sk, scope)` must be a
  byte-stable, version-tagged artefact suitable for embedding in a
  `ViewingKeyIssuance` proof bundle (#562). Its size SHOULD be
  bounded by the scope width but MUST NOT scale linearly with the
  number of in-scope VTXOs.
- **Domain separation from existing tweaks.** The scope-derivation
  hash MUST use a tagged-SHA256 with a tag distinct from
  `DarkConfidentialStealthTweakV1` (ADR M5-DD), the memo HKDF info
  string (`dark-confidential/memo/v1`, ADR-0003), and the opening
  hash in ADR-0005 (`DarkConfidentialOpeningV1`). A future bug that
  feeds the wrong derived value into the wrong slot must fail to
  validate cryptographically rather than producing a valid-but-
  wrong artefact in another domain.
- **No new curve assumption.** All keys live on `secp256k1`. No
  pairing curves, no ed25519, no ZK-circuit-only constructions.
- **Test-vector parity.** Scope-derivation vectors
  `(master_scan_sk, scope_id) → (scoped_scan_sk, scoped_scan_pk)`
  MUST be byte-exact across implementations.
- **`scope` is a public-information predicate over the announced
  VTXO.** The recipient's scanning loop (#558) decides which
  `scoped_scan_sk` to use by reading public data on the VTXO (the
  round id) and computing the scope identifier deterministically
  from it. There is no secret routing channel between the sender
  and the recipient about which scope was used — the answer is
  always "the scope of the round this VTXO landed in".

## Options Considered

The design space splits along two axes:

- **Enforcement strength** — does the auditor's key fail
  cryptographically on out-of-scope inputs (hard scope) or only by
  CLI convention (soft scope)?
- **Scope axis** — what is the natural unit the scope is measured
  in: rounds, blocks, calendar windows, or sender-controlled tags?

Four concrete schemes are evaluated below. They are not independent
and combining axes naively produces unsound constructions; the four
options below are the practical points in the space.

### Option 1 — Soft scope: share the master `scan_sk`, ignore-by-tooling

The user hands the auditor their master `scan_sk` and a "scope
declaration" (`{ start_round: R_a, end_round: R_b }`) printed in
ASCII. The auditor's CLI is built to skip any VTXO whose `round_id`
falls outside `[R_a, R_b]`.

- **Cryptographic enforcement**: none. The master scan_sk decrypts
  every memo ever addressed to the user. Every byte of the user's
  payment history is one config flag away.
- **Auditor-key leak blast radius**: catastrophic. A leaked key
  unmasks the user's lifetime graph. Because the leaked key IS the
  master scan_sk, the user's *only* recovery path is to rotate
  their meta-address — i.e. publish a new identifier, re-key every
  counterparty, and accept that any incoming payment to the old
  meta-address is permanently surveilled.
- **Multiple scopes**: every "scope" issued is the same key.
  Issuing five "different" auditors keys is issuing the same key
  five times. There is no concept of cryptographic independence.
- **Scope axis**: arbitrary (the CLI can filter on anything). This
  is the only axis on which soft scope is flexible — but the
  flexibility is a property of the CLI, not the protocol.
- **Sender-side complexity**: zero. The sender encrypts to the
  master `scan_pk` exactly as ADR-0003 specifies today. No change.
- **Recipient-side complexity**: zero. The recipient uses their
  master `scan_sk` exactly as today.
- **Auditor UX**: trivial. The auditor receives a single 32-byte
  secret and a date range.
- **Threat model**: requires trusting the auditor's tooling to
  honestly drop out-of-scope VTXOs. In a regulated context, the
  auditor's tooling is operated by a third party (often a SaaS
  audit vendor) outside the user's control. "Trust their CLI" is
  not a satisfactory threat model for selective disclosure.
- **Verdict**: rejected. The whole point of selective disclosure is
  *cryptographic* selective disclosure. Soft scope is not a
  selective-disclosure mechanism; it is a selective-non-disclosure
  honour system. We document it as the baseline against which the
  hard-scope options improve.

### Option 2 — Hard scope: per-round scoped scan key derivation

For each VTXO, the sender derives a **per-round scoped recipient
pubkey** by tweaking the recipient's master `scan_pk` with the round
id:

```text
t_R = TaggedHash("DarkConfidentialViewingScopeV1", round_id_bytes)
scoped_scan_sk_R = scan_sk + t_R               (mod n_secp256k1)
scoped_scan_pk_R = scan_pk + t_R · G
```

The sender encrypts the memo to `scoped_scan_pk_R` (i.e. the
per-output ECDH in ADR-0003 uses `scoped_scan_pk_R` instead of the
master `scan_pk`). The recipient's scanning loop, on seeing a VTXO
in round `R`, computes `t_R` from the public round id, derives
`scoped_scan_sk_R = scan_sk + t_R`, and decrypts.

A viewing key issued for "rounds `R_a..R_b`" is the **set** of
`scoped_scan_sk_R` for `R ∈ [R_a, R_b]`. Each scalar is independent
of every other (different `t_R`); leaking one `scoped_scan_sk_R`
yields the master `scan_sk` only by combination with another
`scoped_scan_sk_R'` (since `scoped_scan_sk_R - scoped_scan_sk_R' =
t_R - t_R'`, which is a known public quantity, so the difference of
any two leaked scoped keys IS the master modulo a known offset —
see "Cross-cutting threat: collusion across two leaks" in the
Decision section for why we mitigate this).

- **Cryptographic enforcement**: hard. The auditor cannot decrypt a
  VTXO outside the scope because the auditor does not hold
  `scoped_scan_sk_R` for that round.
- **Auditor-key leak blast radius**: bounded to the per-round
  scoped keys handed over. Leak one round's key → one round's VTXOs
  unmasked.
- **Multiple scopes**: independent if the keys handed over do not
  overlap. Auditor A (R_a..R_b) and Auditor B (R_c..R_d) hold
  cryptographically independent key sets if `[R_a, R_b] ∩ [R_c,
  R_d] = ∅`. Overlapping scopes share keys for the overlapping
  rounds; this is by construction (a single round has one scoped
  key) and is acceptable because both auditors were authorised for
  that round.
- **Scope axis**: round id, natively. Time bounds collapse to
  round bounds at the scope-issuance layer ("Q3 2026" → "rounds
  R_q3_start..R_q3_end" computed at issue time from a published
  round-by-timestamp index).
- **Sender-side complexity**: small additive change to ADR-0003.
  The sender computes `t_R` (one tagged hash, one scalar add, one
  point op) per output and encrypts to `scoped_scan_pk_R`.
- **Recipient-side complexity**: small additive change to the
  scanning loop (#558). On each announced VTXO, derive `t_R` from
  the public round id, derive `scoped_scan_sk_R`, run ECDH against
  `ephemeral_pk` as today.
- **Auditor UX**: receives one bundled artefact containing the
  per-round scoped keys for the requested range, plus a signed
  attestation. For a 90-day audit at 60 rounds/hr (~130k rounds),
  that's ~4 MB of scalar bytes — too large to copy-paste, fine to
  exchange as a file.
- **Storage**: per-round scaling makes the key bundle linear in
  round count. At a year-long scope and Steady-state's 60
  rounds/hr (~525k rounds), the bundle is ~17 MB. Operational but
  bulky; pushes toward Option 3's coarser-grained bucketing.
- **Verdict**: cryptographically clean but the linear-in-rounds
  bundle size argues for an epoch granularity coarser than one
  round. Option 3 generalises this and is the recommended
  refinement.

### Option 3 — Hard scope: epoch-bucketed scoped scan key (chosen)

Bucket rounds into fixed-width **epochs**. Within an epoch, every
VTXO uses the same scoped recipient pubkey:

```text
epoch_id_of(round_id)        = round_id_to_epoch(round_id)
                             = floor(round_height / EPOCH_SIZE_ROUNDS)
                                                    // round_height is the
                                                    // monotonically-increasing
                                                    // round counter from #540
t_E                          = TaggedHash(
                                  "DarkConfidentialViewingScopeV1",
                                  epoch_id_le_bytes,            // 8 B little-endian
                              )
                             // tagged-hash output reduced mod n_secp256k1
scoped_scan_sk_E             = scan_sk + t_E              (mod n_secp256k1)
scoped_scan_pk_E             = scan_pk + t_E · G
```

The sender encrypts the memo to `scoped_scan_pk_E` for the epoch
the round falls into. A viewing key for `[E_a, E_b]` is the set of
`scoped_scan_sk_E` for `E ∈ [E_a, E_b]` — one scalar per epoch in
the range, not one per round.

- **Cryptographic enforcement**: hard. Identical to Option 2.
- **Auditor-key leak blast radius**: one epoch's worth of VTXOs per
  leaked scoped scalar. With `EPOCH_SIZE_ROUNDS = 1024` and 60
  rounds/hr, one epoch is ~17 hours. Leaking the full audit bundle
  for a 90-day scope reveals 90 days; leaking one scalar from
  inside the bundle reveals one epoch (~17 hours).
- **Multiple scopes**: independent if their epoch sets do not
  overlap. Same independence properties as Option 2 modulo the
  coarsening.
- **Scope axis**: epoch id, with round id mapping deterministically
  to epoch via integer division. Time bounds map through the same
  round-height-by-timestamp index.
- **Sender-side complexity**: identical cost to Option 2 (one
  tagged hash, one scalar add, one point op per output) but
  computed once per *epoch* and cached for the duration of an
  epoch in steady state.
- **Recipient-side complexity**: same as Option 2; the epoch
  derivation is a single integer division on the round height.
- **Auditor UX**: receives a bundle containing one scoped scalar
  per epoch in range. For a 90-day audit at default
  `EPOCH_SIZE_ROUNDS = 1024` and 60 rounds/hr, that's 90 days *
  24 h/day * 60 rounds/hr / 1024 rounds/epoch ≈ 127 epochs ≈ 4 KB
  of scalars. For a year-long audit, ~510 epochs ≈ 16 KB. Fits in
  a single file, easy to share, easy to verify.
- **Granularity tradeoff**: a 1024-round epoch is the granularity
  at which a leaked scoped scalar cannot be narrowed further. If
  an auditor is malicious and leaks one in-range scalar, the
  attacker who recovers the scalar can decrypt every memo for
  every VTXO in that 17-hour window addressed to this user.
  Smaller epoch sizes shrink that window but bloat the bundle
  size proportionally. `EPOCH_SIZE_ROUNDS = 1024` is the
  recommended default because it keeps year-scale bundles in the
  10s-of-KB range while keeping the per-leak window at "less than
  one calendar day" — small enough to be operationally useful as
  audit evidence, not so small that the bundle becomes
  unmanageable.
- **Verdict**: chosen — see "Decision".

### Option 4 — Tag-based / topic-scoped viewing keys

Instead of a temporal scope, the scope is a sender-declared **topic
tag** carried in the memo. The sender specifies a topic
(`tag = "trading-desk-A"`, `tag = "personal"`) at output time, and
the recipient's scanning logic distinguishes per-topic scoped keys.

The construction would be analogous to Option 3 but with `t_topic
= TaggedHash("DarkConfidentialViewingScopeV1", tag_bytes)`.

- **Cryptographic enforcement**: hard.
- **Scope axis**: sender-declared, not protocol-derived.
- **Sender-side complexity**: the sender must know the recipient's
  topic at output time. This requires the recipient to publish
  topics as part of their meta-address, which leaks the topic
  taxonomy publicly (Auditor A and Auditor B both learn that the
  user has *some* trading-desk relationship just by reading the
  meta-address; this is a metadata regression).
- **Recipient-side complexity**: the scanning loop needs to know
  the topic associated with each scoped scan key. Storing the
  topic plaintext in the public memo defeats stealth-scanning;
  binding the topic to the scoped key derivation requires the
  sender to be in a specific business relationship with the
  recipient (which is a centralisation regression — the protocol
  no longer supports anonymous senders to a topic-scoped wallet).
- **Auditor UX**: trivial (the auditor receives one scalar per
  topic) but requires the user to maintain a topic taxonomy that
  is public-by-construction.
- **Composability with M5 stealth-address scheme**: poor. M5
  guarantees that a single meta-address looks identical to every
  sender; topic-scoping forces the sender to choose a topic at
  output time, which couples sender behaviour to recipient
  metadata.
- **Compliance fit**: actually a poor fit for the institutional
  audit case: regulators ask for "Q3 2026 activity" not for
  "the trading-desk-A activity" and certainly do not accept
  "trust the user's topic labelling".
- **Verdict**: rejected for v1. Documented for completeness; if a
  future use case justifies topic-scoped keys (e.g. per-merchant
  payment receipts), they layer additively on top of the temporal
  scope without changing the M6 design. Tracked as
  **[FU-VK-TOPIC]**.

### Evaluation matrix

| Criterion                                                         | Opt 1 (soft) | Opt 2 (per-round)        | Opt 3 (epoch-bucketed)       | Opt 4 (topic)            |
|-------------------------------------------------------------------|--------------|--------------------------|------------------------------|--------------------------|
| Cryptographic enforcement                                         | **No**       | Yes                      | Yes                          | Yes                      |
| Auditor-key leak: blast radius                                    | **Lifetime** | One round per scalar     | One epoch per scalar         | One topic per scalar     |
| Multiple independent scopes                                       | No           | Yes                      | Yes                          | Yes                      |
| Audit-bundle size (90 days at 60 r/h)                             | 32 B         | ~4 MB                    | **~4 KB** (default epoch)    | O(topic count)           |
| Audit-bundle size (1 year)                                        | 32 B         | ~17 MB                   | **~16 KB** (default epoch)   | O(topic count)           |
| Sender-side overhead per output                                   | 0            | 1 hash + 1 scalar add    | 1 hash + 1 scalar add        | 1 hash + 1 scalar add    |
| Recipient scan overhead per output                                | 0            | 1 hash + 1 scalar add    | 1 hash + 1 scalar add        | depends on topic count   |
| Time-bounded scopes via the same primitive                        | n/a          | Yes (R_a..R_b)           | Yes (E_a..E_b)               | **No** (orthogonal)      |
| Sender needs out-of-band info from recipient                      | No           | No (round id is public)  | No (epoch id is public)      | **Yes** (topic taxonomy) |
| Stealth-address compatibility                                     | Yes          | Yes                      | Yes                          | **Partial**              |
| Spend authority unaffected                                        | Yes          | Yes                      | Yes                          | Yes                      |
| Recovery from auditor-key leak                                    | Rotate meta-address (catastrophic) | Wait for scope expiry | Wait for scope expiry | Rotate the leaked topic |
| Two-leak collusion → master `scan_sk`                             | n/a (already master) | **Yes** (mitigated by domain separation; see Decision) | **Yes** (mitigated by domain separation; see Decision) | Yes |
| Verifier surface (#564)                                           | Trivial      | Linear in rounds         | Linear in epochs (small)     | Linear in topics         |
| Compatible with M5 (#553) meta-address                            | Yes          | Yes                      | Yes                          | Partial                  |
| Suitable for regulatory audit periods                             | Yes (untrusted) | Yes                   | Yes                          | **No**                   |

## Decision

**Adopt Option 3 — epoch-bucketed scoped scan keys with
`EPOCH_SIZE_ROUNDS = 1024` as the default**. The recipient pubkey
the sender encrypts the memo to (the slot ADR-0003 currently spells
"the recipient's `scan_pk`") is the **scoped** pubkey
`scoped_scan_pk_E` for the epoch the round falls into. The mathematical
construction is the standard secp256k1 additive-tweak used elsewhere
in the workspace (BIP-32 unhardened CKD, Taproot key-tweaking, the
M5-DD stealth one-time-key tweak); the novelty is the choice of
input to the tweak (`epoch_id`) and the domain-separation tag
(`DarkConfidentialViewingScopeV1`).

### Numerical bounds

- `EPOCH_SIZE_ROUNDS = 1024`.
  At Steady-state's 60 rounds/hr this is ≈ 17 hours per epoch. A
  90-day audit covers ≈ 127 epochs (≈ 4 KB of scalars); a year
  covers ≈ 510 epochs (≈ 16 KB). The choice balances
  per-leak-window granularity against bundle size; smaller values
  bloat the bundle without materially shrinking the per-leak
  window in any operationally-relevant sense (a sub-hour leak
  window is the same audit evidence as a sub-day leak window),
  larger values inflate the per-leak blast radius. 1024 is the
  point at which both knobs are within 10× of the "natural" audit
  granularity (one calendar day).

- `MIN_SCOPE_EPOCHS = 1`. A scope MUST cover at least one epoch.
  Issuing a viewing key for "exactly one round" is a future
  per-round-disclosure primitive (see #565 — VTXO selective reveal)
  and is NOT what the viewing key is for. The minimum epoch span
  rule prevents the disclosure surface from collapsing into the
  per-VTXO-reveal surface and producing two redundant
  primitives.

- `MAX_SCOPE_EPOCHS = 8192` (≈ 16 years at default config). A
  single viewing key MUST NOT cover more than 8192 epochs; users
  who want a longer audit issue multiple bundles. The bound
  prevents accidental issuance of a "view forever" key (the most
  common misuse pattern in soft-scope schemes elsewhere) and caps
  the bundle size at ≈ 256 KB.

- `EPOCH_ID_BYTES = 8`. The epoch id is encoded as a `u64` little-
  endian when fed to the tagged hash. 8 bytes is enough for >
  500B-year-equivalent at default config; future deployments
  cannot exhaust the space.

These bounds are operator-tunable (epoch size in particular) per
the `[disclosure.viewing_key]` section in `config.toml` (see
"Operator config" below), but the defaults are pinned by this ADR
and a deployment that diverges MUST republish its constants to
counterparties.

### Construction

```text
// ----- public, deterministic -----
EPOCH_SIZE_ROUNDS:  u64    = 1024                            // ADR default
SCOPE_TAG          : ASCII = "DarkConfidentialViewingScopeV1"

epoch_of(round_height: u64) -> u64
    = round_height / EPOCH_SIZE_ROUNDS                       // integer div

t_E(epoch_id: u64) -> Scalar
    = TaggedHash(SCOPE_TAG, epoch_id.to_le_bytes())          // 32 bytes
      |> scalar_reduce(mod n_secp256k1)                      // 32 bytes

// ----- recipient, derives from master + public scope -----
scoped_scan_sk(scan_sk: SecretKey, epoch_id: u64) -> SecretKey
    = scan_sk.add_tweak(t_E(epoch_id))                       // mod n

scoped_scan_pk(scan_pk: PublicKey, epoch_id: u64) -> PublicKey
    = scan_pk.add_exp_tweak(t_E(epoch_id))                   // point add t_E·G

// ----- sender, encrypts memo to scoped pubkey for the round's epoch -----
encrypt_memo(plaintext, ephemeral_sk, scan_pk_master, round_height, one_time_pk)
    let E             = epoch_of(round_height)
    let scoped_scan_pk_E = scoped_scan_pk(scan_pk_master, E)
    return encrypt_memo_v1(plaintext, ephemeral_sk, scoped_scan_pk_E, one_time_pk)
                                  // existing ADR-0003 routine, unchanged
                                  // beyond the recipient pubkey it consumes
```

The recipient's scanning loop derives the matching scoped scalar
from `scan_sk` plus the public `round_height` of each announced
VTXO, then runs the ADR-0003 ECDH against `ephemeral_pk` exactly as
today. The auditor, holding `scoped_scan_sk_E`, runs the same
routine for in-scope VTXOs and gets a successful AEAD verification;
out-of-scope VTXOs decrypt to garbage and the AEAD tag fails — the
auditor receives `None`, not a partial result.

### Why a tagged-hash additive tweak (and not the alternatives)

- **Versus a multiplicative tweak (`scoped_scan_sk = scan_sk *
  t_E mod n`).** Multiplicative tweaks lose the additive
  homomorphism we need for compatibility with ADR M5-DD's
  one-time-key derivation (`one_time_pk = spend_pk + H(...) · G`,
  also additive). Mixing additive and multiplicative tweaks across
  the scan/spend domains creates non-trivial interaction risks
  (e.g. an attacker who learns `scoped_scan_sk_E` and `t_E` can
  recover `scan_sk = scoped_scan_sk_E - t_E`; under multiplicative
  tweak the recovery would be `scan_sk = scoped_scan_sk_E *
  inverse(t_E)` which is structurally similar but the analysis
  diverges across the codebase). One scheme everywhere keeps the
  audit story uniform.

- **Versus an HKDF-based derivation.** HKDF-SHA256 over `(scan_sk,
  epoch_id)` would produce a fresh independent-looking secret per
  epoch with no algebraic relationship to `scan_sk`. That breaks
  the property we want most: from `scan_sk` plus public
  `epoch_id`, the recipient MUST be able to derive
  `scoped_scan_sk_E` and use it as a secp256k1 scalar in the
  ECDH. A non-algebraic derivation forces the sender to encrypt
  memos to fully-fresh public keys per epoch, which means the
  user must publish a stream of per-epoch pubkeys (unbounded
  publishing burden) rather than a single meta-address — the
  meta-address invariant from #553 collapses.

- **Versus pairing-based delegation (e.g. BLS-based hierarchical
  identity-based encryption).** Pairings would let us construct
  scoped keys with provable forward security (a leaked
  `scoped_scan_sk_E` revealing only data inside `[E, E+w]` for
  some bounded `w`), but require introducing a new curve
  (BLS12-381 or BN254) and a new audit surface. The workspace
  pin on `secp256k1 = 0.29` (ADR-0001) and the milestone scope
  ("compliance, not novel cryptography") rule it out for v1.
  Tracked as **[FU-VK-PAIRING]** for a v3 spec if the regulatory
  bar tightens.

- **Versus splitting the scan key tree at BIP-32.** A clean
  alternative is to derive `scoped_scan_sk_E` as a hardened BIP-32
  child of `scan_sk` at path `m/44'/1237'/{a}'/0'/{epoch_id}`.
  Hardened CKD gives strong sub-tree isolation but forces the
  derivation to *flow downward* — the recipient's scanner needs
  access to the parent xprv (or one xprv per epoch precomputed)
  to derive `scoped_scan_sk_E` on-the-fly. The sender CANNOT
  derive `scoped_scan_pk_E` from the published meta-address alone
  under hardened CKD; the meta-address would have to publish an
  xpub at `m/44'/1237'/{a}'/0'`, and that xpub plus a hardened
  child gives nothing (hardened CKD requires the parent priv
  bytes). Switching to unhardened CKD restores the public
  derivation property at the cost of the xpub-leak footgun
  (ADR M5-DD analysis Option 3 — xpub-leak + one priv-leak →
  master priv recovery). The additive-tweak construction adopted
  here gives the public-derivation property *without* the
  xpub-leak risk, because the master `scan_pk` is already public
  by construction (it lives in the meta-address) and the tweak
  is publicly derivable from the round id.

### Why `EPOCH_SIZE_ROUNDS = 1024`

- **One leaked scalar = one epoch unmasked.** At 60 rounds/hr,
  one epoch is ≈ 17 hours. Operationally, this is the
  granularity below which audit evidence is "the same calendar
  day" and above which it crosses a calendar boundary. Auditors
  asking for evidence at finer-than-one-day granularity would
  use the per-VTXO reveal primitive (#565), not viewing keys.
- **Bundle size is manageable.** At 1024 rounds/epoch, a year-long
  audit is ≈ 510 epochs ≈ 16 KB; 32-bit URL safe base64 encoded
  it remains under 22 KB. Fits in an email attachment, a clipboard
  paste, or a single QR code series.
- **Power-of-two for cheap arithmetic.** `epoch = round_height >>
  10` on the hot path of the scanning loop. The overhead per
  announced VTXO is one shift, one tagged hash, one scalar add —
  dominated by the secp256k1 ECDH that ADR-0003 already costs.
- **Round-rate-stable.** A bootstrap deployment at 12 rounds/hr
  has ≈ 85-hour epochs; a stress-load deployment at 360 rounds/hr
  has ≈ 3-hour epochs. The semantic meaning of "epoch" shifts
  with the operator's round rate, but the audit-bundle math
  stays predictable in terms of epochs-per-time-window. The
  operator-tunable `EPOCH_SIZE_ROUNDS` lets a deployment with an
  unusual round rate retune the per-leak window to its preferred
  calendar granularity.

### Why round_height (not block height, not wall-clock time)

- **Round_height is the canonical Ark monotonic counter.** Issue
  #540 (transparent VTXO commitment) already publishes
  `round_height` as a strictly monotonic per-round counter. Every
  confidential VTXO references the round it was created in.
  Computing `epoch_id` from `round_height` is one integer division
  on data the sender, recipient, and any third-party verifier
  already have.
- **Block height is L1 plumbing.** Bitcoin block height is an
  upstream-paced clock the operator does not control. Tying
  scope semantics to block height would mean a 60-minute
  L1 reorg at the audit boundary changes which VTXOs an
  auditor can decrypt — a stability hazard for compliance
  workflows.
- **Wall-clock time is operator-attested.** Using a UNIX
  timestamp as the scope axis would require the operator to
  publish a signed `(round_height, timestamp)` index that
  every party trusts. Adding "the operator must sign the clock"
  as a soundness requirement reopens the whole "trust the
  operator" question this milestone is designed to keep
  scoped-and-bounded. Operators MAY publish a wall-clock-to-
  round-height index as a convenience for users who think in
  calendar terms, but the index is advisory; the canonical
  scope axis is `round_height`.

### `ViewingKey` wire format

A `ViewingKey` is a versioned, length-prefixed sequence of
per-epoch scalars plus the metadata needed for verification:

```text
ViewingKey wire layout (v1)
+-------------------+-------+----------------------------------+
| version_byte      |  1 B  | 0x01                             |
| issuer_scan_pk    | 33 B  | recipient's master scan_pk       |
|                   |       | (compressed secp256k1)           |
| epoch_size_rounds |  8 B  | u64 LE — 1024 by default         |
| start_epoch       |  8 B  | u64 LE — inclusive lower bound   |
| end_epoch         |  8 B  | u64 LE — INCLUSIVE upper bound   |
| epoch_count       |  4 B  | u32 LE — = end_epoch - start_epoch + 1 |
| scoped_scalars[]  | 32 B * epoch_count, secp256k1 scalars in BE |
+-------------------+-------+----------------------------------+
```

Total: `1 + 33 + 8 + 8 + 8 + 4 + 32 * epoch_count` bytes. At
default config a 90-day key is `1 + 33 + 8 + 8 + 8 + 4 + 32 *
127 = 4126 bytes`; a year-long key is ≈ 16 KB. This wire format
is embedded as the `payload` of a `ViewingKeyIssuance` proof
bundle (#562); the bundle's outer envelope adds the user
signature and the proof-type tag.

The bundle MUST be signed by the user's spend key (the same
authority that authorises VTXO spends — the user attests "yes I
issued this key"). The spend signature is over the canonical
serialisation of the ViewingKey wire layout; verifiers (#569)
recompute the canonical bytes and check the signature. Without
the signature, an attacker who recovers `scoped_scan_sk_E` from
some other channel could publish a "ViewingKey" claiming the
victim issued it — the signature pins issuance authority.

### Verifier-side enforcement

The auditor's verifier accepts a ViewingKey if and only if:

1. `version_byte = 0x01`. Unknown versions return a typed error
   (per #562's extensibility requirement).
2. `start_epoch <= end_epoch`.
3. `epoch_count = end_epoch - start_epoch + 1`.
4. `epoch_count >= MIN_SCOPE_EPOCHS` and `epoch_count <=
   MAX_SCOPE_EPOCHS`.
5. The bundle's outer signature verifies under the issuer's
   master spend pubkey (recovered from on-chain data via the
   user's published meta-address — see #553).
6. Every `scoped_scalars[i]` is a valid secp256k1 scalar (non-zero,
   < `n`).
7. **Soundness check:** for at least one `i ∈ [0, epoch_count)`,
   the scalar `scoped_scalars[i]` matches the expected derivation:

   ```text
   expected_pk = scan_pk_master + t_E(start_epoch + i) · G
   actual_pk   = scoped_scalars[i] · G
   assert expected_pk == actual_pk
   ```

   The verifier MAY check all `i`; the cheap path checks one
   sampled `i` and accepts on match. A maliciously-issued bundle
   that includes a *wrong* scoped scalar at index `i` will fail
   the spot check with high probability if the verifier randomises
   the sample. Production verifiers (#569) MUST randomise.

To decrypt an in-scope VTXO at round `R`:

```text
E              = epoch_of(R)
if E < start_epoch or E > end_epoch:
    return None        // out of scope
i              = E - start_epoch
scoped_sk      = SecretKey::from_slice(scoped_scalars[i])
shared_point   = scoped_sk · ephemeral_pk
[run ADR-0003 memo decryption with shared_point]
```

Out-of-scope VTXOs are short-circuited at step 1 (no AEAD attempt
made). The cryptographic enforcement is therefore in two layers:
(a) the auditor's tooling cannot find a `scoped_sk` for an
out-of-scope round in the bundle, so it returns `None`; (b) even
if the auditor's tooling skipped the bundle-range check and
attempted decryption with an arbitrary scalar from the bundle,
the AEAD tag would fail because the scoped pubkey on the wire
does not match. We rely on (a) for performance and (b) for
soundness; either alone suffices for the security property.

### Cross-cutting threat: collusion across two leaks

**Risk.** If an attacker obtains `scoped_scan_sk_E1` and
`scoped_scan_sk_E2` (two scalars from the same user's bundle),
the attacker computes:

```text
delta = scoped_scan_sk_E1 - scoped_scan_sk_E2
      = (scan_sk + t_E1) - (scan_sk + t_E2)
      = t_E1 - t_E2
```

`delta` is a publicly-derivable quantity (anyone can compute `t_E1
- t_E2`). The leak does NOT recover `scan_sk` — the cancellation
already happened. However, the attacker now knows
`scoped_scan_sk_E1 = scan_sk + t_E1` exactly (they had it). They
can subtract `t_E1` (public!) and recover `scan_sk` directly:

```text
scan_sk = scoped_scan_sk_E1 - t_E1     (mod n)
```

So a single leaked scoped scalar **already** reveals `scan_sk` to
anyone who knows the tweak input. This is the structural
consequence of using an additive tweak with a publicly-known
input — the "additive" half is the security loss.

**Why this is acceptable for the chosen design:**

- The attacker who recovers `scan_sk` from a leaked `scoped_scan_sk_E`
  recovers **scanning authority for every past and future VTXO**
  to the user's master meta-address. This is the worst case in
  Option 1 (soft scope) too — the only difference is that Option 3
  reaches it via an *issued* viewing key rather than via the
  user directly handing over the master scan_sk.
- This means the viewing-key construction is **only as good as
  the auditor's key-handling discipline.** A leaked
  `ViewingKey` for any non-trivial scope reveals the user's
  master scan_sk; the auditor MUST treat the bundle as
  catastrophic-loss-on-leak. The "blast radius" advertised in the
  evaluation matrix above is the *post-decryption* blast radius
  (which VTXOs the auditor can decode with the tooling provided),
  not the *cryptographic* blast radius.
- **Mitigation (mandatory):** the `ViewingKey` MUST NOT be
  treated as a routine credential. The CLI surface (#568) MUST
  print a prominent warning when issuing a viewing key:
  "*This bundle reveals every VTXO ever paid to your meta-address
  if it leaks. Treat it as you would your wallet seed for the
  scope's lifetime.*" The `disclose viewing-key` command MUST
  require an explicit confirmation prompt (or a
  `--i-understand-viewing-key-risk` flag for scripted use) before
  emitting the bundle.
- **Mitigation (recovery path):** if a viewing-key bundle leaks,
  the user's recovery is to **rotate the master meta-address** —
  publish a new `MetaAddress` (#553) with a new
  `(scan_sk, spend_sk)` pair, instruct counterparties to use the
  new address. Past payments to the old meta-address remain
  scannable by the leak attacker; future payments to the new
  meta-address are not. This is the same recovery as Option 1's
  catastrophic case. The advantage of Option 3 over Option 1 is
  that the *expected* leak rate is much lower because the
  bundle is only handed to specific auditors with limited
  scope, not to the world.
- **Future-work mitigation:** a v2 design (post-CV-M6) can replace
  the additive-tweak construction with a forward-secure
  hierarchical IBE scheme (pairings) where leaking a scoped key
  reveals *only* the in-scope ciphertexts, *not* the master.
  Tracked as **[FU-VK-PAIRING]**. v1 ships the additive-tweak
  scheme with the explicit caveat above and the rotation
  recovery path.

This trade-off is not a defect of the chosen option; it is the
property of any scheme that lets the recipient derive
`scoped_scan_sk_E` from `(scan_sk, public_epoch_id)` without
running an interactive protocol. Schemes that avoid the trade-off
(pairing-based IBE, forward-secure encryption) are out of scope
for v1.

### Operator config

```toml
[disclosure.viewing_key]
# Number of rounds per epoch. Default 1024 (~17 h at 60 r/h).
# Operators may retune to match their round rate; deployments
# with non-default values MUST publish the value alongside the
# meta-address so counterparties can compute matching scoped pubkeys.
epoch_size_rounds = 1024

# Minimum number of epochs a single viewing key may cover. Hard
# floor: 1. Cannot be configured below 1.
min_scope_epochs = 1

# Maximum number of epochs a single viewing key may cover. Hard
# ceiling: 8192. Operators may lower this for stricter audit
# policy; cannot raise above the hard ceiling.
max_scope_epochs = 8192
```

Prometheus metrics exported by the wallet daemon for the
viewing-key issuance flow:

- `disclosure_viewing_keys_issued_total` — counter, total bundles
  emitted by this wallet since process start.
- `disclosure_viewing_key_scope_epochs` — histogram, buckets:
  `[1, 4, 16, 64, 256, 1024, 4096, 8192]`. Helps users monitor
  whether they tend to issue narrow or wide-scope keys.

Verifier-side metrics live with #569.

### Specification

The full canonical specification, in pseudo-Rust, lives in
`crates/dark-confidential/src/disclosure.rs` (currently a stub —
see `crates/dark-confidential/src/disclosure.rs:1`) and is owned
by #564. The behavioural contract:

```rust
// pseudocode — implementation lives in #564

pub struct ViewingKey {
    version: u8,
    issuer_scan_pk: PublicKey,
    epoch_size_rounds: u64,
    start_epoch: u64,
    end_epoch: u64,
    scoped_scalars: Vec<SecretKey>,    // length = end_epoch - start_epoch + 1
}

pub struct ViewingKeyScope {
    pub start_round_height: u64,
    pub end_round_height:   u64,        // INCLUSIVE
    pub epoch_size_rounds:  u64,        // typically the wallet's configured default
}

pub fn issue_viewing_key(
    spend_sk: &SpendKey,                // wallet's master spend key (signs issuance)
    scan_sk:  &ScanKey,                 // wallet's master scan key (derives scoped scalars)
    scope:    &ViewingKeyScope,
) -> Result<ViewingKey, IssueError> {
    let start_epoch = scope.start_round_height / scope.epoch_size_rounds;
    let end_epoch   = scope.end_round_height   / scope.epoch_size_rounds;
    let epoch_count = end_epoch.checked_sub(start_epoch).ok_or(IssueError::EmptyScope)? + 1;

    if epoch_count < MIN_SCOPE_EPOCHS as u64 { return Err(IssueError::ScopeTooNarrow); }
    if epoch_count > MAX_SCOPE_EPOCHS as u64 { return Err(IssueError::ScopeTooWide); }

    let mut scoped = Vec::with_capacity(epoch_count as usize);
    for e in start_epoch..=end_epoch {
        let t_e = scope_tweak(e);                       // TaggedHash, mod n
        let scoped_sk = scan_sk.add_tweak(t_e)?;        // mod n
        scoped.push(scoped_sk);
    }

    Ok(ViewingKey {
        version: 0x01,
        issuer_scan_pk: scan_sk.pubkey(),
        epoch_size_rounds: scope.epoch_size_rounds,
        start_epoch,
        end_epoch,
        scoped_scalars: scoped,
    })
    // The outer ViewingKeyIssuance bundle (proof_bundle, #562) wraps this
    // payload with version, proof_type=ViewingKeyIssuance, and a signature
    // by spend_sk over the canonical bytes.
}

pub fn decrypt_vtxo(
    viewing_key: &ViewingKey,
    vtxo: &ConfidentialVtxo,
) -> Option<(Amount, Blinding)> {
    let e = vtxo.round_height / viewing_key.epoch_size_rounds;
    if e < viewing_key.start_epoch || e > viewing_key.end_epoch {
        return None;     // hard out-of-scope short-circuit
    }
    let i = (e - viewing_key.start_epoch) as usize;
    let scoped_sk = &viewing_key.scoped_scalars[i];
    decrypt_memo_v1(scoped_sk, vtxo.ephemeral_pk, vtxo.encrypted_memo, vtxo.one_time_pk)
        .ok()
        .map(|plain| (plain.amount, plain.blinding))
}
```

### Test vectors

Three positive vectors and three negative scenarios are
materialised byte-exactly in
`docs/adr/vectors/m6-viewing-key-vectors.json` (created by the
implementation issue #564; this ADR specifies the inputs and
outputs the vectors must contain).

Vector V1 — single-epoch scope, default epoch size:

| Field                              | Value                                                                          |
|------------------------------------|--------------------------------------------------------------------------------|
| `mnemonic` (BIP-39, no passphrase) | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| `account`                          | `0`                                                                            |
| `epoch_size_rounds`                | `1024`                                                                         |
| `start_round_height`               | `0`                                                                            |
| `end_round_height`                 | `1023`                                                                         |
| → `start_epoch`                    | `0`                                                                            |
| → `end_epoch`                      | `0`                                                                            |
| → `epoch_count`                    | `1`                                                                            |
| → `t_E[0]` (32 B BE)               | *(materialised by #564)*                                                       |
| → `scoped_scan_sk[0]` (32 B BE)    | *(materialised by #564)*                                                       |
| → `scoped_scan_pk[0]` (33 B compressed) | *(materialised by #564)*                                                  |

Vector V2 reuses the same mnemonic with a 7-epoch scope
(`start_round_height = 0, end_round_height = 7167`) to exercise
the loop. Vector V3 covers a non-zero `start_round_height` (≈
hour 100,000) to exercise epoch-id arithmetic at high counters.

Negative scenarios:

- **N1**: scope with `epoch_count = 0` (degenerate range) — MUST
  return `IssueError::EmptyScope`.
- **N2**: scope with `epoch_count > MAX_SCOPE_EPOCHS` — MUST
  return `IssueError::ScopeTooWide`.
- **N3**: decryption attempt against a VTXO whose
  `round_height` falls outside `[start_round_height,
  end_round_height]` — MUST return `None`, MUST NOT raise an
  AEAD-failure error (the short-circuit at scope-boundary check
  precedes the AEAD attempt; testing both layers is the point of
  the negative scenario).

The vector generator lives at `contrib/viewing-key-vector-gen/`
(created by #564), reuses the `secp256k1 = 0.29` and
`chacha20poly1305 = 0.10` pins from the workspace, and
deterministically reproduces each vector given the input
mnemonic and scope.

## Consequences

### Positive

- **Cryptographic enforcement of scope.** An auditor with a
  ViewingKey for `[E_a, E_b]` cannot decrypt any VTXO with
  `epoch_id ∉ [E_a, E_b]`. The decision to honour the scope is
  made by mathematics (no scoped scalar in the bundle for
  out-of-scope epochs), not by tooling.
- **Audit-bundle size is operationally manageable.** A 90-day
  audit at default config is ≈ 4 KB; a year is ≈ 16 KB. Bundles
  fit comfortably in any out-of-band exchange channel (email,
  signed PDF attachment, encrypted file share).
- **Multiple concurrent independent scopes.** The user can issue
  three viewing keys for three auditors, with overlapping or
  disjoint scopes, without cross-pollination beyond the
  necessary overlap (an auditor authorised for an epoch will
  receive that epoch's scoped scalar; if two auditors are both
  authorised for the same epoch, they both get the same scalar
  — there is one scoped scalar per epoch per user).
- **Same primitive supports time and round bounds.** A user who
  thinks "Q3 2026" and an auditor who thinks "rounds 100k–200k"
  both end up with the same on-disk artefact; the round-by-
  timestamp index is a UI convenience, not a separate
  cryptographic mechanism.
- **Spend authority unaffected.** The viewing-key construction
  touches the scan domain only. The recipient's `spend_sk`,
  the one-time-key derivation in #554, and the unilateral-exit
  script in ADR-0005 are unchanged. A leaked viewing key cannot
  spend anything.
- **Sender-side change is one tagged-hash and one point op.**
  ADR-0003's memo encryption gains one tweak step (compute
  `scoped_scan_pk_E` from the recipient's published `scan_pk`)
  and proceeds unchanged. The on-the-wire memo bytes have
  the same shape as today; the `ephemeral_pk · scoped_scan_pk_E`
  shared point is what changes vs. `ephemeral_pk · scan_pk`,
  and that change is invisible to the operator (the operator
  never sees either pubkey on the wire).
- **Operator visibility unchanged.** The operator does not
  learn that a user issued a viewing key, who the auditor is,
  or what the scope is. Issuance is a purely off-chain
  artefact.
- **Forward-compatible with #564, #568, #569, #570.** The wire
  format is versioned, the issuance API is bounded, and the
  verifier surface is the bundle-decoder defined in #562.
  Future viewing-key-related work layers additively.

### Negative / follow-ups

- **One leaked scoped scalar reveals `scan_sk`.** Documented in
  detail under "Cross-cutting threat" above. Mitigated by the
  "treat-as-seed" UX warning at issuance, the scope-bound
  expiry, and the rotation recovery path. A future v2 with
  pairing-based IBE would close this gap; tracked as
  **[FU-VK-PAIRING]**.
- **Memo decryption cost increases by one scalar add per
  scanned VTXO.** Negligible in absolute terms (the secp256k1
  ECDH dominates) but worth noting for the scanning-loop
  benchmarks.
- **Sender-side cost increases by one tagged hash per output.**
  Tagged-hash is two SHA-256s; on commodity hardware this is
  sub-microsecond per output. Imperceptible.
- **Recipient publishes `scan_pk` and the epoch tweak is
  publicly derivable.** This is the property that buys us
  sender-side determinism, but it means the user's
  `scoped_scan_pk_E` is computable by anyone who knows the
  master `scan_pk` (which is everyone — `scan_pk` is in the
  meta-address). The privacy implication: an observer who sees
  multiple confidential outputs and tries to correlate them by
  the recipient pubkey embedded in the AEAD's AAD does NOT
  gain a new linkability primitive (the AAD already binds to
  the per-output `one_time_pk`, which is unique per output by
  ADR M5-DD). Worth documenting; not a regression.
- **Operator-tunable `epoch_size_rounds` is a coordination
  surface.** A deployment that runs at non-default
  `epoch_size_rounds` MUST publish the value alongside the
  meta-address (or in operator-side documentation) so
  counterparties can compute matching scoped pubkeys.
  Mismatch results in encryption to the wrong recipient
  pubkey — which the recipient cannot decrypt at all (so
  payment fails closed, not open). The CLI MUST print the
  effective `epoch_size_rounds` when issuing a viewing key
  and warn if it differs from `1024`.
- **No revocation list.** The design relies on scope expiry as
  the sole revocation mechanism. A user who wants to revoke an
  already-issued viewing key before its scope expires has no
  protocol-level option — the auditor still holds the bundle
  and the bundle is still cryptographically valid for in-scope
  VTXOs. The only mitigation is rotation of the master
  meta-address (catastrophic, see "Cross-cutting threat").
  Adding an on-protocol revocation list (operator publishes
  "this viewing key is revoked") would re-introduce
  operator-mediated trust into the disclosure flow and is
  rejected for v1. Tracked as **[FU-VK-REVOKE]** if the
  product reality demands it post-launch.
- **No support for "rolling window" scopes.** A scope is a fixed
  `[E_a, E_b]` at issuance time. A user who wants "give the
  auditor visibility into the most-recent 90 days, indefinitely"
  must reissue a new bundle every 90 days. Acceptable for the
  v1 audit use cases (regulators demand point-in-time
  evidence, not continuous rolling windows); tracked as
  **[FU-VK-ROLLING]** if SaaS-audit integrations need it.
- **No partial-amount disclosure via the viewing key.** The
  viewing key reveals the full `(amount, blinding)` plaintext
  for every in-scope VTXO. A user who wants to give an auditor
  visibility into "the fact that there was a payment, but not
  the amount" must use a different primitive (range proof,
  #566). The viewing key is the all-or-nothing-within-scope
  primitive by design.
- **CLI bundle size at MAX_SCOPE_EPOCHS is 256 KB.** Beyond
  the conveniently-shareable threshold for an emailed
  attachment. Operators / users issuing maximum-scope keys
  should expect to use a file-share channel (signed S3 URL,
  encrypted USB, etc.).
- **Soundness check is probabilistic by default.** The verifier
  spot-checks one scoped scalar per bundle; a malicious issuer
  could produce a bundle with one valid and (epoch_count - 1)
  garbage scalars, and the cheap spot check would detect it
  with `1 - 1/epoch_count` probability. Production verifiers
  (#569) MUST randomise the sample index. A paranoid verifier
  MAY check all scalars; the cost is `O(epoch_count)` point
  ops, which at year-scale is < 50ms on commodity hardware.
- **Bundle versioning leaks scheme version to the auditor.** The
  `version_byte` in the wire layout is observable to the
  auditor. If the user's wallet ships v2 (pairing-based) and
  the auditor's verifier is still v1, the bundle is rejected
  with a typed error. This is the correct behaviour; documented
  for the audit-tooling integration story.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen this ADR before landing.

#### #564 (`ViewingKey` derivation, issuance, verification) MUST

- Implement `issue_viewing_key(spend_sk: &SpendKey, scan_sk:
  &ScanKey, scope: &ViewingKeyScope) -> Result<ViewingKey,
  IssueError>` exactly as specified above. The signature MUST
  take the spend key explicitly (it signs the issuance bundle)
  and the scan key explicitly (it derives the scoped scalars);
  combining them into a single "wallet handle" parameter is
  forbidden because the spend and scan domains are deliberately
  separated by ADR M5-DD.
- Implement `decrypt_vtxo(viewing_key: &ViewingKey, vtxo:
  &ConfidentialVtxo) -> Option<(Amount, Blinding)>` with the
  hard out-of-scope short-circuit specified above. Out-of-scope
  VTXOs MUST return `None`, MUST NOT return any error variant
  ("decryption failed" is reserved for the in-scope-but-
  malformed case).
- Use the tagged-hash domain `DarkConfidentialViewingScopeV1`
  for the scope tweak. The tag is byte-exact and pinned by this
  ADR; renaming reopens this ADR and breaks all extant test
  vectors.
- Encode `epoch_id` as `u64` little-endian (8 bytes) when
  feeding the tagged hash. Big-endian is forbidden — every
  other `u64` in the workspace's wire formats is little-endian
  (memo length fields, vtxo amounts).
- Embed the `ViewingKey` payload as the `payload_bytes` field
  of a `ViewingKeyIssuance`-typed proof bundle (#562). The
  bundle's outer signature is computed over the canonical
  bytes of the payload, by the issuer's spend_sk.
- Reject `epoch_count < MIN_SCOPE_EPOCHS` and `epoch_count >
  MAX_SCOPE_EPOCHS` at issuance with typed errors
  `IssueError::ScopeTooNarrow` and `IssueError::ScopeTooWide`.
- Provide a property test asserting that for every `(seed,
  account, scope)`:
  - The bundle round-trips through canonical encoding (issue →
    encode → decode → decrypt-an-in-scope-VTXO succeeds).
  - Out-of-scope VTXOs return `None`.
  - Decryption with the issuer's `scan_sk` directly
    (bypassing the bundle) and decryption via the bundle yield
    the same `(amount, blinding)` for in-scope VTXOs (the
    bundle is functionally equivalent to selective scan_sk
    use).
- Embed test vectors V1–V3 from this ADR as Rust fixtures in
  `crates/dark-confidential/tests/viewing_key_vectors.rs` and
  assert byte-equality of `(scoped_scan_sk[i], scoped_scan_pk[i])`
  for each vector.

#### #564 MUST NOT

- Couple the viewing-key derivation to the recipient's
  `spend_sk`. The spend key participates ONLY as the issuance-
  bundle signer; it MUST NOT contribute to the scoped-scalar
  derivation. Mixing the two domains breaks ADR M5-DD's
  scan/spend isolation invariant.
- Provide an API that returns scoped scalars without the
  surrounding `ViewingKey` structure. The structure carries the
  scope metadata (`epoch_size_rounds`, `start_epoch`, `end_epoch`)
  that the verifier needs to interpret the scalars correctly;
  exporting raw scalars without metadata is an attractive-
  nuisance API.
- Implement `From<ScanKey> for ViewingKey` or any other implicit
  conversion. ViewingKey issuance is an explicit, scope-bounded
  operation.
- Hardcode `epoch_size_rounds = 1024` anywhere outside the wallet's
  config-default. Library APIs MUST take `epoch_size_rounds`
  explicitly via `ViewingKeyScope`.

#### #565 (VTXO selective reveal) interaction

VTXO selective reveal is a distinct primitive that does NOT use
viewing keys; it reveals `(amount, blinding)` for one specific
VTXO via a signed bundle. The two primitives are disjoint by
design: viewing keys are scoped-and-passive (auditor decrypts
many VTXOs over time); VTXO reveal is one-shot-and-active (user
proves one statement about one output). #565 MUST NOT depend on
the viewing-key construction; #564 MUST NOT depend on the
VTXO-reveal construction. Both consume the same proof-bundle
envelope from #562.

#### #568 (`ark-cli disclose viewing-key`) MUST

- Accept a scope argument in either round-id form
  (`--scope-rounds R_a..R_b`) or wall-clock form
  (`--scope-time 2026-07-01..2026-09-30`). The wall-clock form
  resolves to round heights via the operator's published
  round-by-timestamp index (operator policy; advisory).
- Print a prominent warning before emitting the bundle:
  *"This viewing-key bundle, if leaked, reveals every VTXO
  ever paid to your meta-address (not just the in-scope ones).
  Store it as carefully as your wallet seed for the scope's
  duration."* Plus one of:
  - an interactive `[y/N]` confirmation, OR
  - a `--i-understand-viewing-key-risk` flag for scripted use.
- Print the effective `epoch_size_rounds` and warn if it
  differs from `1024` (operator-tuned deployment).
- Default `--scope-rounds` is REQUIRED (no default). Issuing a
  viewing key without an explicit scope is a misuse pattern;
  the CLI MUST refuse.
- Emit the bundle as canonical bytes (binary) by default; with
  `--json` emit a base64-encoded payload inside the JSON
  envelope.

#### #568 MUST NOT

- Provide a "viewing key for everything" mode. Maximum scope is
  `MAX_SCOPE_EPOCHS = 8192`; a request for more is rejected at
  the issuance layer (#564) and the CLI MUST surface the
  rejection rather than silently capping.
- Persist the issued bundle to the wallet's local state. The
  bundle is an artefact for off-band sharing; storing it
  alongside the wallet seed defeats the threat model
  (workstation compromise = bundle leak = `scan_sk` leak).
  The CLI MUST stream the bundle to stdout / stdin / a
  user-specified file path; persistence in the wallet DB is
  forbidden.

#### #569 (`VerifyComplianceProof` for ViewingKey bundles) MUST

- Verify the outer signature against the issuer's master
  spend pubkey (recovered from the `issuer_scan_pk` field of
  the wire layout via the user's published meta-address per
  #553).
- Randomly sample at least one `i ∈ [0, epoch_count)` and
  verify `scoped_scalars[i] · G == scan_pk_master + t_E(start_epoch
  + i) · G`. Production deployments MAY check all `i`; the
  randomised sample is the minimum.
- Return `FAILED_PRECONDITION` with a typed `UnknownBundleVersion`
  detail when `version_byte != 0x01`. Future versions land as
  additional handlers; the dispatch MUST be exhaustive.
- Be unauthenticated and rate-limited at the IP layer (per #569's
  acceptance criteria). The verifier sees only public bundle
  bytes; there is no user-secret leak surface to gate.

#### #569 MUST NOT

- Decrypt VTXOs as part of verification. The verifier checks
  bundle integrity; it does NOT use the bundle to read
  ciphertexts (which would require the operator to learn what
  the auditor learns — an operator-side metadata leak).

#### #570 (compliance guide) MUST

- Document the "treat-as-seed" UX warning at issuance with the
  exact phrasing used by the CLI in #568.
- Provide a worked example of issuing a 90-day viewing key to
  an external auditor (`ark-cli disclose viewing-key
  --scope-time 2026-07-01..2026-09-30 --auditor-pubkey ...`)
  and the corresponding verification flow.
- Document the rotation recovery path for a leaked bundle:
  rotate the master meta-address, re-key counterparties, accept
  that pre-leak payments to the old meta-address are
  permanently surveilled by the leak attacker.
- Document the disjointness from #565 (VTXO selective reveal):
  viewing keys are for "show me a window"; VTXO reveal is for
  "show me one fact". Auditors should not ask for a viewing key
  when a single VTXO reveal would do.

#### Documentation MUST

- Update ADR-0003's "AAD" section to clarify that the
  recipient pubkey the sender encrypts to is `scoped_scan_pk_E`
  (the master `scan_pk` is the *base*; the on-the-wire AEAD AAD
  binds to the scoped pubkey, not the master). This is a
  documentation update; the wire format is unchanged.
- Reference this ADR from `docs/architecture.md` under the
  Selective Disclosure & Compliance section.

## Open Questions / TODO

- **Forward-secure viewing keys via pairing-based IBE.** Tracked
  as **[FU-VK-PAIRING]**. The v2 design would replace the
  additive-tweak scheme with a hierarchical-IBE construction
  where leaking a scoped key reveals only in-scope ciphertexts
  (the master `scan_sk` is not recoverable from any scoped
  key in isolation). Requires introducing a pairing-friendly
  curve (BLS12-381 or BN254) into the workspace, which is a
  substantial audit-surface expansion. Out of scope for CV-M6;
  reopened if the regulatory bar tightens or if a leak
  incident demonstrates the additive-tweak's blast-radius
  property is operationally unacceptable.

- **On-protocol revocation list for viewing keys.** Tracked
  as **[FU-VK-REVOKE]**. The current design relies on scope
  expiry as the sole revocation mechanism. A user who wants
  to revoke an already-issued bundle before its scope expires
  has no protocol-level option. An on-protocol revocation
  list would let the user publish "viewing key X is
  revoked"; the verifier (#569) would refuse bundles whose
  hash matches a revoked entry. Re-introduces operator-
  mediated trust into the disclosure flow (the operator is
  the natural publisher of the revocation list); rejected for
  v1 on principle but reopened if a leak incident demonstrates
  the rotation recovery path is too costly in practice.

- **Rolling-window scopes.** Tracked as **[FU-VK-ROLLING]**.
  An auditor relationship that needs continuous visibility
  into the "last 90 days, ongoing" requires the user to
  reissue the bundle every 90 days. Acceptable for the
  point-in-time-audit use cases; reopened if SaaS-audit
  integrations demand it.

- **Topic-scoped viewing keys.** Tracked as **[FU-VK-TOPIC]**.
  Per Option 4 in the analysis above; layers additively on
  the temporal scope without changing the M6 design. v1 ships
  the temporal scope only.

- **Round-by-timestamp index for wall-clock scope arguments.**
  Tracked as **[FU-VK-CALENDAR]**. The CLI accepts wall-clock
  scope arguments (`--scope-time 2026-Q3`) by resolving against
  the operator's round-by-timestamp index. The index is operator-
  policy; if it becomes a usability bottleneck, the protocol
  could publish a deterministic round-rate-attestation that lets
  the wallet self-resolve. Out of scope for v1.

- **Hardware-wallet-attested viewing-key issuance.** Tracked
  as **[FU-VK-HW]**. The viewing-key bundle is signed by the
  spend key; if the spend key lives on a hardware device, the
  hardware must be able to sign the canonical bundle bytes.
  Hardware support is out of scope for v1 (matches ADR M5-DD's
  [FU-STEALTH-HW]); the path choice in this ADR does not
  preclude HW support — the bundle bytes are a standard
  64-byte BIP-340 Schnorr signature input.

- **Multi-issuer (joint-account) viewing keys.** Tracked as
  **[FU-VK-MULTI]**. A 2-of-2 joint account that wants to
  issue an audit bundle requires joint signing on the
  issuance bundle and a way to derive the scoped scan
  scalars from a multi-party scan key. Not on the v1 path;
  the joint-account use case itself is not in CV-M6.

- **Cross-implementation test-vector exchange.** Tracked as
  **[FU-VK-VECTOR-XCHECK]**. Once a second implementation
  exists in another language (TypeScript wallet SDK), the
  `m6-viewing-key-vectors.json` file MUST be re-run against
  it; any byte-mismatch reopens this ADR.

- **Bundle compression.** Tracked as **[FU-VK-COMPRESS]**.
  At MAX_SCOPE_EPOCHS the bundle is 256 KB. Standard zstd
  compression on a vector of 32-byte secp256k1 scalars yields
  a near-zero ratio (the scalars are uniform random); a
  delta-encoding scheme (`scoped_scalars[i] - scoped_scalars[i-1]
  mod n`) is also uniform random and does not compress. The
  bundle is incompressible by design; reopened only if a
  future construction lets us emit a polylogarithmic
  representation (e.g. tree-based scoped-scan-key derivation
  where the bundle is a single root and a depth proof per
  in-scope epoch).

- **Disclosure of `epoch_size_rounds` mismatches.** Tracked
  as **[FU-VK-EPOCH-MISMATCH]**. If the user's wallet and the
  auditor's verifier disagree on `epoch_size_rounds` (e.g.
  the user runs a non-default deployment), the bundle's
  `epoch_size_rounds` field disambiguates, but the auditor
  must trust the field. A MITM that rewrites
  `epoch_size_rounds` in the bundle is detected by the outer
  signature (the field is part of the signed canonical bytes),
  so the integrity is fine; the open question is the UX
  affordance for surfacing the mismatch ("this user runs at
  epoch_size = 4096, default is 1024 — proceed?").

- **Threat-model document for viewing-key-holding auditors.**
  Tracked as **[FU-VK-THREAT-MODEL]**. A formal threat-model
  doc covering "auditor as honest-but-curious", "auditor as
  malicious", "auditor's machine compromised by external
  attacker", "subpoena attack on auditor for the bundle" is
  out of scope for this ADR and lives with the
  privacy-deployment workstream.

## References

- Issue #561 (this ADR)
- Issue #564 — viewing key derivation and scoped access
  (consumes the construction defined here)
- Issue #565 — VTXO selective reveal with commitment opening
  (orthogonal disclosure primitive)
- Issue #566 — bounded-range compliance proofs (orthogonal)
- Issue #567 — source-of-funds proofs (orthogonal)
- Issue #568 — `ark-cli` disclose/verify commands
- Issue #569 — `VerifyComplianceProof` gRPC endpoint
- Issue #570 — compliance guide
- Issue #562 — compliance proof bundle format (defines the
  outer envelope this ADR's payload nests inside)
- Issue #563 — disclosure proof types shipping at launch
- Issue #553 — dual-key meta-address (defines `scan_sk` /
  `scan_pk` that this ADR tweaks)
- Issue #540 — round commitment / `round_height` source of truth
- ADR-0001 — secp256k1-zkp integration (curve choice)
- ADR-0002 — nullifier derivation (domain-separation idiom)
- ADR-0003 — confidential VTXO memo format (this ADR substitutes
  `scoped_scan_pk_E` for `scan_pk` in the recipient slot)
- ADR-0005 — confidential VTXO unilateral-exit script
  (uses an independent domain-separation tag
  `DarkConfidentialOpeningV1`; this ADR's
  `DarkConfidentialViewingScopeV1` does not collide)
- ADR M5-DD stealth derivation (defines `scan_sk` / `scan_pk`
  derivation paths and the `DarkConfidentialStealthTweakV1`
  domain — disjoint from this ADR's tag)
- ADR M5-DD announcement pruning (round-id retention; the
  audit horizon for viewing keys is bounded by the
  `ARCHIVAL_HORIZON_ROUNDS` of that ADR — beyond the archival
  horizon, the underlying VTXO ciphertexts are no longer
  scannable from announcements alone, so a viewing key
  covering pre-archival epochs has no operator data to apply
  to)
- BIP-340 — Schnorr signatures (tagged-hash construction
  reused for the scope tweak)
- `crates/dark-confidential/src/disclosure.rs` — stub module
  (line 1) that #564 implements against this ADR
- `crates/dark-confidential/src/stealth/keys.rs` — `ScanKey`
  / `SpendKey` newtypes this ADR's API consumes
- Test vectors:
  `docs/adr/vectors/m6-viewing-key-vectors.json`
  (created by #564)
- Vector generator: `contrib/viewing-key-vector-gen/`
  (created by #564)
