# ADR-0006: ECVRF dependency strategy

- **Status:** Accepted
- **Date:** 2026-04-30
- **Milestone:** VON-M1 (PSAR cryptographic primitives)
- **Drives:** #651 → unblocks #652 → #653; forward-references #654 / #655
- **Affects:** new `dark-von` workspace crate; existing crates untouched.

## Context

Issue #651 asks us to pick a strategy for the **ECVRF** primitive that
underpins the VON nonce-derivation wrapper (issues #654 and #655).
ECVRF is specified by [RFC 9381]; we need it on **secp256k1** because
our entire signing stack (BIP-340 / BIP-327 / `secp256k1 = 0.29`) lives
on that curve and the VON output `R = r·G` must be usable as a MuSig2
sub-nonce in `dark-signer`.

The issue lists three candidate paths: depend on an external crate,
vendor and patch one, or implement in-tree. This ADR records the
candidate survey and the decision.

[RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381

## Requirements

- ECVRF on **secp256k1** (the curve already used by every other
  signing component in this workspace; an EdDSA / P-256 VRF cannot
  produce points that compose with our MuSig2 nonces).
- `keygen`, `prove(sk, alpha) -> (beta, pi)`, `verify(pk, alpha, beta, pi)`
  surface, returning `Result<_, EcvrfError>` per
  `docs/conventions/errors.md`.
- Workspace crypto pins preserved: `secp256k1 = 0.29`,
  `secp256k1-zkp = 0.11`, `bitcoin = 0.32`. Anything that drags in a
  second curve impl (OpenSSL, native `libsecp256k1` outside the
  vendored `-sys` crate) is disqualified — we do not maintain a second
  curve context (this is the same constraint ADR-0001 imposed).
- Determinism: identical `(sk, alpha)` produce identical
  `(beta, pi)` on every supported target.
- Compiles for the four release targets (`x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`,
  `aarch64-apple-darwin`).
- `#![forbid(unsafe_code)]` at crate level (matches `dark-confidential`
  per ADR-0001).

## Candidates

### Option 1 — `vrf = 0.2.4` (witnet/vrf-rs)

Witnet's `vrf` crate is the only Rust crate on crates.io that exposes
ECVRF with a **secp256k1** ciphersuite (`Secp256k1Sha256Tai`,
implementing the secp256k1 variant from `draft-irtf-cfrg-vrf-05`,
predecessor of RFC 9381).

| Attribute | Value |
|---|---|
| Latest version | `0.2.4` (2020-04-23) |
| License | MIT |
| Curve impl | OpenSSL via `openssl = 0.10` |
| Last upstream commit | 2022-09-22 (essentially dormant) |
| Test vectors | Inlined in `tests/`; sourced from the draft |
| RFC 9381 alignment | Tracks **draft-05**, not the published RFC. Final RFC dropped secp256k1 from the appendix; ciphersuite tag and challenge-derivation differ from later drafts. |

**Disqualifiers** (any one is sufficient):

- **Pulls OpenSSL** as a transitive system dependency. Our release
  matrix relies on `cross` and the `-sys`-style vendored builds set
  up in ADR-0001; introducing OpenSSL recreates the per-target build
  configuration we deliberately avoided.
- **Two curve contexts.** OpenSSL's secp256k1 is a separate
  implementation from `libsecp256k1` (used by both `secp256k1` and
  `secp256k1-zkp`). Points/scalars are not interoperable without
  serialise-to-bytes round-trips; constant-time guarantees are
  different.
- **Dormant upstream.** No release in nearly six years; the secp256k1
  ciphersuite the crate implements is from a draft that did not make
  it into the published RFC. We would inherit a frozen spec.

### Option 2 — `vrf-rs` (other GitHub forks)

Several `vrf-rs` GitHub repositories exist (e.g. `roganartu/vrf-rs`).
None are published to crates.io, none have been touched since 2021,
and the maintained ones target Ed25519 only. **Disqualified**: no
secp256k1 surface, no release artefact, no path to a stable
dependency.

### Option 3 — Vendor & extract from larger codebases

ECVRF on secp256k1 ships inside two large production codebases:
DFINITY's Internet Computer (`dfinity/ic`, Apache-2.0) and Chia
(`Chia-Network/chiapos` / consensus crates, Apache-2.0). Both have
audited code, but:

- They are not packaged as standalone crates and depend on their
  host project's curve abstractions (e.g. `ic_crypto_internal_*`).
- Extracting the relevant module would mean vendoring 5–15 KLOC and
  rewriting the curve-op layer to talk to `secp256k1 = 0.29`. At that
  point we are ~80 % of the way to Option 4 anyway, with a heavier
  audit surface (other-project code we now own) and no licensing
  benefit over Option 4.

### Option 4 — In-tree on `secp256k1 = 0.29`

Implement ECVRF directly on top of the curve we already use, with our
own ciphersuite tag. Per RFC 9381 §5 the construction is:

```
prove(sk, alpha):
    H        = hash_to_curve(pk, alpha)        // RFC 9381 §5.4.1.1 TAI
    Gamma    = sk · H
    k        = nonce_generation(sk, H)         // RFC 9381 §5.4.2.2
    c        = challenge(pk, H, Gamma, k·G, k·H)  // §5.4.3
    s        = k + c·sk  (mod n)
    pi       = (Gamma || c || s)               // §5.5
    beta     = proof_to_hash(pi)               // §5.2

verify(pk, alpha, beta, pi):
    decode (Gamma, c, s) from pi
    H        = hash_to_curve(pk, alpha)
    U        = s·G − c·pk
    V        = s·H − c·Gamma
    c'       = challenge(pk, H, Gamma, U, V)
    return c == c' AND beta == proof_to_hash(pi)
```

`hash_to_curve` is the only non-mechanical piece. We pick the
**try-and-increment** variant ("TAI") from RFC 9381 §5.4.1.1: hash
counter‖pk‖alpha with SHA-256, attempt to lift the digest to a curve
point, increment the counter on failure. Probability of failure per
attempt ≈ ½, so an expected 2 attempts per call. **Not constant-time**
in the number of attempts, which RFC 9381 calls out — acceptable here
because `alpha` is public (it is the schedule input, not a secret).

What we own under Option 4:

- ~150 LOC of ECVRF logic (`prove`, `verify`, `proof_to_hash`).
- ~50 LOC of TAI hash-to-curve.
- ~50 LOC of proof encoding/decoding.
- A new ciphersuite tag (this ADR proposes
  `DARK-VRF-SECP256K1-SHA256-TAI` — see "Ciphersuite" below).

## Evaluation matrix

| Criterion | Opt 1 (`vrf` crate) | Opt 2 (`vrf-rs` forks) | Opt 3 (vendor IC/Chia) | **Opt 4 (in-tree)** |
|---|---|---|---|---|
| secp256k1 today | Yes (draft-05) | No | Yes (after extraction) | Yes |
| Curve interoperable with `secp256k1 = 0.29` | No (OpenSSL) | N/A | After rewriting curve layer | Yes |
| RFC 9381 alignment | Draft-05 only | N/A | Yes | Yes (TAI variant) |
| New system deps | OpenSSL | N/A | None | None |
| Audit surface added | Vendored OpenSSL behaviour + crate code | N/A | 5–15 KLOC of someone else's code | ~250 LOC we own |
| Upstream liveness | Dormant since 2020 | Dormant since 2021 | Active, but not as a crate | N/A |
| WASM / `cross` story | Has bitten others (OpenSSL on `wasm32`) | N/A | Inherits host project's | Inherits `secp256k1`'s — passes |
| Test-vector sourcing | Inlined draft-05 vectors | N/A | Inherited from host project | We emit our own, pinned in `tests/data/` |
| Effort | Low to integrate, high to maintain | N/A | High (vendoring + rewrite) | Medium (~250 LOC + tests) |

## Decision

**Adopt Option 4: implement ECVRF in-tree** in a new
`crates/dark-von` workspace crate, on top of `secp256k1 = 0.29`.

### Ciphersuite

We use a project-specific ciphersuite tag,
**`DARK-VRF-SECP256K1-SHA256-TAI`**, structurally identical to
RFC 9381's `ECVRF-P256-SHA256-TAI` (§5.5) with the curve parameters
substituted. The literal byte tag (suite_string) is the ASCII bytes of
that name. This is honest about the fact that **RFC 9381 does not
contain official secp256k1 test vectors** — §A covers Ed25519 and
P-256 only, and the secp256k1 ciphersuite present in earlier drafts
was dropped from the final RFC. We do not gain RFC-9381-conformance
by adopting Option 1; the `vrf` crate is also draft-aligned, not
RFC-aligned. By owning the ciphersuite we can point to a single
self-contained spec (this ADR + the module docstring) instead of
hand-waving about which draft we track.

The encoding choices below are what concretely defines the
ciphersuite:

| Field | Choice | RFC 9381 §reference |
|---|---|---|
| `suite_string` | ASCII bytes of `DARK-VRF-SECP256K1-SHA256-TAI` | §5.5 |
| Hash | SHA-256 (output 32 B) | §5.5 |
| Point encoding | 33-byte compressed (SEC1) | §5.5 |
| Scalar encoding | 32 B big-endian | §5.5 |
| `hash_to_curve` | TAI with separator byte `0x01`, terminator `0x00` | §5.4.1.1 |
| Challenge `c` truncation | 16 B (truncated SHA-256 per §5.4.3 P-256/secp256k1 convention) | §5.4.3 |
| Proof layout | `Gamma (33 B) || c (16 B) || s (32 B)` = **81 bytes** | §5.5 |
| `proof_to_hash` `beta` | SHA-256("suite_string \|\| 0x03 \|\| Gamma \|\| 0x00") = 32 B | §5.2 |
| Nonce generation | RFC 6979 deterministic ECDSA-style nonce over `(sk, H)` | §5.4.2.2 fallback |

### Tagged-hash domain separation

The internal SHA-256 calls inside `hash_to_curve`, `challenge`, and
`proof_to_hash` are domain-separated by the literal `suite_string` and
the §-defined separator bytes (e.g. `0x01` for `hash_to_curve`,
`0x02` for `challenge`, `0x03` for `proof_to_hash`). We do **not**
use BIP-340 tagged-hash midstate caching for these calls — RFC 9381
defines the inputs without a tagged-hash framing, and adding one
would deviate from §5 in a way callers couldn't verify against the
spec. (BIP-340 tagged hashing is reserved for the higher-level
`H_nonce` in #656, where we control the domain.)

## Test-vector strategy (constraint on #653)

Because RFC 9381 §A has no secp256k1 vectors, **#653 cannot literally
"parse the official §A vectors"** — the wording in that issue's
acceptance criteria refers to a state of the world that does not
exist. The test-vector strategy this ADR pins is:

1. **Self-consistency vectors** (mandatory): 16 vectors covering
   small/large `alpha`, low/high `sk` Hamming weight, near-zero and
   near-`n` scalars. These pin our own `prove` output for fixed
   inputs; they catch any post-merge regression in the implementation.
2. **Cross-implementation vectors** (informational): the eight
   secp256k1 vectors from `vrf` crate's `tests/secp256k1_sha256_tai.rs`
   are committed as `tests/data/witnet_v0_2_4_secp256k1_tai.json`,
   loaded with a `WITNET_VRF_VECTORS` const, and exercised under
   `#[ignore]`. They are draft-05-aligned and **expected to differ
   from our suite_string-tagged outputs** — they exist as a sanity
   check that our hash-to-curve geometry agrees on the curve points
   while the proof bytes differ only in the `suite_string` /
   separator-byte placement.
3. **Negative vectors**: mutated proof bytes, mutated `alpha`,
   mutated public key — each must reject with the appropriate
   `EcvrfError` variant.

#653 is amended in scope: replace "RFC 9381 §A test vectors" with
the three categories above. The acceptance criteria's intent (no
ciphersuite drift) is preserved by category 1.

## Consequences

### Positive

- **One curve, one context.** Stays on `secp256k1 = 0.29` like the
  rest of the workspace. No second curve impl, no OpenSSL.
- **Audit surface is small and ours.** ~250 LOC of well-specified
  crypto in `crates/dark-von/src/ecvrf.rs`, all behind
  `#![forbid(unsafe_code)]`. Easier to review than vendoring 5+ KLOC.
- **Deterministic test vectors we control.** Self-consistency
  vectors (#653 category 1) are emitted from our own `prove` and
  pinned; any future divergence trips the suite immediately.
- **Forward path to RFC 9381 if it ever adds secp256k1.** Because
  our ciphersuite differs from §5.5 only in the `suite_string` and
  challenge-truncation length, switching to a future RFC-blessed
  variant is a constant-time edit in `ecvrf.rs::SUITE_STRING` plus a
  new vector set. No callers see the change.

### Negative / follow-ups

- **No third-party audit.** We are not vendoring audited code; we
  are writing it. The compensating controls are: small surface,
  unsafe-forbidden, RFC-9381-mechanical construction, and category-1
  vectors. **Follow-up [FU-VRF-AUDIT]:** book an external review of
  `crates/dark-von/src/ecvrf.rs` before tagging `v0.1-von-psar`
  (§paper-track milestone, issue #694).
- **TAI is not constant-time in counter attempts.** RFC 9381 §5.4.1.1
  acknowledges this. Acceptable because `alpha` is public schedule
  input. **Follow-up [FU-VRF-SSWU]:** evaluate switching to SSWU
  (constant-time hash-to-curve) if a future caller passes secret
  `alpha`. None of #654 / #655 / #657 do.
- **Custom ciphersuite tag.** Reviewers reading "ECVRF" expect
  RFC 9381 §A vectors to apply. The module docstring on
  `dark_von::ecvrf` must lead with the ciphersuite name and a
  pointer to this ADR; #652's acceptance criterion *"Publicly
  documented choice of ciphersuite"* maps onto this.

### Cross-cutting — constraints on downstream issues

These are not suggestions; they are requirements for this ADR's
soundness. Any deviation must reopen ADR-0006 before landing.

- **#652 (ECVRF impl)** MUST register
  `crates/dark-von` in the workspace with **only**
  `secp256k1 = { version = "0.29", features = ["hashes", "rand"] }`,
  `sha2 = "0.10"`, `thiserror = "2.0"`, `zeroize` (for `SecretKey`
  hygiene), and `serde` (for `Proof` round-trip). No new curve crate.
  `#![forbid(unsafe_code)]` at crate level.
- **#652** MUST expose `pub const SUITE_STRING: &[u8]` set to the ASCII
  bytes of `DARK-VRF-SECP256K1-SHA256-TAI`, and `pub const PROOF_LEN:
  usize = 81`. The proof byte layout is exactly as in the table
  above; do not deviate.
- **#653** is amended per the test-vector strategy above. The
  category-1 vectors live at
  `crates/dark-von/tests/data/dark_vrf_secp256k1_tai.json` and are
  the hard pass/fail gate. Categories 2 and 3 are additive.
- **#654 (VON wrapper ADR)** must declare which ECVRF outputs the
  wrapper consumes (`beta` only? `Gamma` and `s`?). The wrapper does
  **not** re-derive `H` — that work is done once in `ecvrf::prove`
  and re-exposed via a `Proof::gamma()` accessor.
- **#655 (VON wrapper impl)** reuses `ecvrf::prove` / `ecvrf::verify`;
  the wrapper does not duplicate hash-to-curve.
- **#658 (benches)** must record proof size and prove/verify median
  on the dev machine. If `ecvrf::prove` median exceeds 200 µs on
  Apple-silicon (M-series) reopen this ADR — that would indicate a
  TAI rejection-rate regression.

## References

- Issue #651 (this ADR) and #652–#658 (downstream).
- RFC 9381 — *Verifiable Random Functions (VRFs)*:
  <https://datatracker.ietf.org/doc/html/rfc9381>
- ADR-0001 — sets the precedent that any new curve dependency must
  share `secp256k1`'s context.
- `vrf = 0.2.4`: <https://crates.io/crates/vrf/0.2.4>
- DFINITY IC (informational, not vendored):
  <https://github.com/dfinity/ic>
- `dark-confidential` tagged-hash convention as observed in
  `crates/dark-confidential/src/balance_proof.rs:91-96` (the
  `dark-<crate>/<purpose>/v1` form). Note: ADR-0006 explicitly does
  **not** wrap RFC-9381 hashes with a BIP-340 tagged-hash midstate
  — the higher-level `H_nonce` in #656 does.
