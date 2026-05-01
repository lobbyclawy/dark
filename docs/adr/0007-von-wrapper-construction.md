# ADR-0007: VON nonce-derivation wrapper construction

- **Status:** Accepted
- **Date:** 2026-04-30
- **Milestone:** VON-M1 (PSAR cryptographic primitives)
- **Drives:** #654 → unblocks #655 → #656 → #657 → #658
- **Affects:** new `dark_von::wrapper` module on top of `dark_von::ecvrf`
  (per ADR-0006, #652).

## Context

Issue #654 asks us to choose a construction for the **VON wrapper** that
turns ECVRF outputs into MuSig2-usable nonces. The wrapper has three
hard requirements that pin its shape:

1. **Hidden secret scalar `r`.** PSAR signs MuSig2 rounds where each
   signer contributes `R = r·G`. The nonce scalar `r` must remain known
   only to the operator until a signing transcript exists; publishing
   `r` early breaks MuSig2 unforgeability.
2. **Public, verifiable `R`.** The operator commits to `{R_t}` at setup
   so cohort members can verify the MuSig2 nonce structure at signing
   time without trusting the operator. A verifier with `pk_VON`, `x`,
   `R`, `π` must be able to check binding without consulting the
   operator.
3. **Binding & uniqueness.** For each `(sk_VON, x)` there is exactly
   one `(R, π)` the operator can produce that passes verification.
   Two distinct valid pairs constitute observable equivocation
   evidence.

The issue text suggests two candidates:

- **(a)** ECVRF output `y` plus a Schnorr proof-of-knowledge that `R = r·G` for a fresh scalar `r` deterministically derived from `y` and `x`.
- **(b)** A direct DDH-style VRF returning `(R, π)` with hash-to-curve.

Neither survives close inspection. This ADR records why and pins a
third construction (**(c)**) that does.

## Why (a) and (b) don't work as described

### (a): "r derived from y and x"

The text says "scalar `r` deterministically derived from `y` and `x`",
where `y` is the ECVRF output. By ECVRF's verifiability property,
`y = ECVRF.proof_to_hash(π)` is computable from any valid proof. So
**any verifier with `π` can compute `y`, and therefore `r`** — if `r`
is a function of `y` and public `x`. This violates Requirement 1
(hidden `r`). The Schnorr PoK is then redundant: knowledge of `r` is
public.

The fix is to derive `r` from secret material the verifier doesn't
have — namely `sk_VON`. That moves us out of (a).

### (b): "DDH-style VRF returning (R, π)"

The natural DDH-VRF construction sets `R = sk_VON · H` for
`H = hash_to_curve(pk_VON, x)`. This is exactly ECVRF's `Gamma` point.
But:

- `Gamma = sk_VON · H` and `H = hash_to_curve(pk_VON, x)`. The
  operator does **not** know `dlog_G(H)`, by hash-to-curve construction.
  Therefore the operator does not know `r` such that `Gamma = r·G`.
- MuSig2 requires the contribution to be of the form `r·G` where the
  signer holds the witness `r`. `Gamma` is not.

So (b) yields a verifiable, unique point — but it's not a usable
MuSig2 nonce. Requirement 2 satisfied, Requirement 1 satisfied
(operator knows nothing extra), but the **MuSig2-compat requirement
that is implicit in #655's `Nonce` returning `(r, R, π)` is violated**.

### What both candidates miss

The wrapper has to do **two distinct things** per call: (i) derive a
secret `r` only the operator can compute, and (ii) attach a public
proof that `R = r·G` is canonical for `(sk_VON, x)`. The candidates
collapse these into one ECVRF call, which forces a tradeoff between
hidden `r` and verifiable binding.

## Decision

**Adopt construction (c): HMAC-derived `r` + R-bound ECVRF proof.**

```text
VON.KeyGen() → (sk_VON, pk_VON):
    sk_VON  ← uniform random ∈ [1, n−1]
    pk_VON  ← sk_VON · G

VON.Nonce(sk_VON, x) → (r, R, π):
    1. r        ← H_r(sk_VON, x)                  // HMAC, hidden
    2. R        ← r · G
    3. alpha'   ← x || compress(R)                // 33 B compressed R
    4. (_, π)   ← ECVRF.prove(sk_VON, alpha')     // binds R into proof
    return (r, R, π)

VON.Verify(pk_VON, x, R, π) → bool:
    1. alpha'   ← x || compress(R)
    2. β        ← ECVRF.proof_to_hash(π)
    3. return ECVRF.verify(pk_VON, alpha', β, π).is_ok()
```

`H_r` is HMAC-SHA-256 with the secret-key bytes as the HMAC key and a
domain-separated input:

```text
H_r(sk_VON, x) = bits2octets( HMAC_SHA256(sk_VON_bytes,
                              b"DARK-VON-r-v1" || x) ) mod n
```

`bits2octets … mod n` is the same reduction `dark_von::ecvrf` already
uses for RFC 6979 nonce generation (see `crates/dark-von/src/ecvrf.rs`'s
`bits2octets_mod_q`). If the result is `0` (probability ~`2^-128`), the
wrapper retries with `b"DARK-VON-r-v1\x01" || x` and so on (counter
suffix). This tail handler will essentially never run; #655 will land
the loop with a counter-cap of 256 and surface `VonError::ScalarZero`
on exhaustion.

### Construction-defining encoding

| Field | Choice |
|---|---|
| `H_r` tag | ASCII bytes `DARK-VON-r-v1` |
| `H_r` MAC | HMAC-SHA-256, key = `sk_VON.secret_bytes()` (32 B BE) |
| `H_r` input layout | `tag (13 B) \|\| x (variable)` |
| `R` encoding | 33-byte compressed SEC1 point |
| `alpha'` (ECVRF input) | `x \|\| R_compressed` (variable + 33 B) |
| `π` | ECVRF proof bytes from `dark_von::ecvrf::Proof::to_bytes()` (81 B) |

### MuSig2 two-nonce mapping

BIP-327 MuSig2 requires each signer to publish two nonce contributions
`(R_1, R_2)` per signing round. In the PSAR schedule the two are
distinguished by the `b ∈ {1, 2}` field of `H_nonce(setup_id, t, b)`
(see #656):

```text
At signing index t:
    x_{t,1} = H_nonce(setup_id, t, 1)
    x_{t,2} = H_nonce(setup_id, t, 2)
    (r_{t,1}, R_{t,1}, π_{t,1}) = VON.Nonce(sk_VON, x_{t,1})
    (r_{t,2}, R_{t,2}, π_{t,2}) = VON.Nonce(sk_VON, x_{t,2})
    // r_{t,1}, r_{t,2} fed to MuSig2 sign as (k_1, k_2)
```

Two independent VON calls per `t`. No coupling between `b=1` and `b=2`
beyond domain separation in `H_nonce`. This keeps the wrapper API
agnostic to MuSig2 layout — `wrapper::nonce(sk, x)` does not know `b`.

## Security argument

### Binding (R is uniquely determined by (pk_VON, x))

For honest operator: `r = H_r(sk_VON, x)` is a deterministic function
of `sk_VON` and `x`. Therefore `R = r·G` is unique. The ECVRF proof
`π` over `alpha' = x || R` is itself deterministic under RFC 6979
nonce generation (per ADR-0006). So `(R, π)` is fully determined by
`(sk_VON, x)`.

### Hidden r (verifier cannot recover r)

The HMAC key is `sk_VON.secret_bytes()`. By HMAC-SHA-256 PRF security,
no PPT adversary lacking `sk_VON` can distinguish `H_r(sk_VON, x)`
from a uniformly random scalar with probability non-negligibly above
chance. The verifier sees `(R, π)` but not `r`; the ECVRF proof does
**not** leak `r` because `r` is not algebraically related to `Gamma`,
`c`, or `s` of the ECVRF proof — the proof is over `alpha' = x || R`,
not over `r`.

### Soundness (no forged (R, π) without sk_VON)

Reduces to ECVRF unforgeability of `dark_von::ecvrf` (#652). An
adversary producing `(R*, π*)` such that `VON.Verify(pk_VON, x, R*,
π*) = ⊤` for some `x` not previously queried would, by the
verification procedure, satisfy `ECVRF.verify(pk_VON, x || R*, β*,
π*) = ⊤`. This requires forging an ECVRF proof under `pk_VON` over
the input `x || R*`, which the unforgeability bound from RFC 9381
§5.6 forbids modulo the curve and hash assumptions for secp256k1 and
SHA-256 respectively.

### Equivocation

An operator attempting to publish two valid pairs `(R, π)` and
`(R', π')` with `R ≠ R'` for the same `x` produces two distinct ECVRF
proofs — one over `alpha = x || R`, one over `alpha = x || R'` —
both valid under `pk_VON`. By determinism of the honest construction,
exactly one is the canonical pair; the other proves the operator
deviated from `r = H_r(sk_VON, x)`.

**Equivocation evidence is publishable but not key-extractable.** The
two proofs are evidence that `pk_VON` signed conflicting nonces;
they do **not** allow third parties to recover `sk_VON`. PSAR's
broader threat model (paper §6) treats this as sufficient: the
reputational and protocol-level cost of double-signing is the
deterrent, not key forfeiture. If a future PSAR variant requires
extractable equivocation, a separate ADR will pin a Schnorr-style
DLEQ construction with the standard `s_1 - s_2 / c_1 - c_2`
extraction; **that is out of scope for VON-M1**.

### Soundness caveats

- **Side-channel on `H_r`**. HMAC-SHA-256 with a secret key is
  side-channel-sensitive. The implementation in #655 uses
  `secp256k1::SecretKey::secret_bytes()` to load the key into HMAC;
  callers should keep the `sk_VON` lifecycle within zeroizing
  storage. RFC 6979's nonce generation in `dark_von::ecvrf` has
  the same posture and we mirror it.
- **MuSig2 sub-nonce independence**. `r_{t,1}` and `r_{t,2}` are
  independent only insofar as `x_{t,1} ≠ x_{t,2}` ⇒ HMAC outputs
  differ pseudorandomly. `H_nonce` (#656) must enforce
  `x_{t,1} ≠ x_{t,2}` by construction; #656's tagged-hash domain
  separation does so.
- **`r = 0` edge**. Probability `2^-128`, handled by counter-suffix
  retry in #655. Not a security issue, just a robustness loop.

## Consequences

### Positive

- **Cleanly separates concerns.** `H_r` produces secret `r` (a PRF
  over `sk_VON`); the ECVRF call binds `R` (a public attestation).
  Each primitive does one thing.
- **Reuses #652 verbatim.** No new curve operation; the wrapper is
  ~50 LOC of plumbing on top of existing `ecvrf::prove`/`verify`.
- **Deterministic at every layer.** HMAC + RFC 6979 nonce ⇒
  `(r, R, π)` is byte-identical across runs of the same `(sk_VON, x)`.
  Test-vector pinning in #656 follows directly.
- **MuSig2 two-nonce maps onto a `b ∈ {1, 2}` field of the input,
  not into the wrapper.** The wrapper stays agnostic to MuSig2
  layout, so future signing schemes (Schnorr-non-MuSig2,
  threshold-Schnorr) reuse it without modification.

### Negative / follow-ups

- **Two SHA-256 chains per call.** HMAC-SHA-256 plus the ECVRF call
  (which itself does a TAI hash-to-curve loop). Microbenchmark
  budget in #658 needs to absorb both. Expected `≤ 250 µs` per
  `VON.Nonce` on Apple-silicon based on ECVRF's measured upper
  bound.
- **`H_r` tag is project-specific.** Not aligned with any external
  spec. Same posture as ADR-0006's `SUITE_STRING`. Documented in
  the module docstring on `dark_von::wrapper`.
- **Equivocation evidence is non-extractable.** Documented above
  under "Soundness caveats". **Follow-up [FU-EXTRACT]:** if PSAR
  evolves to need key-extractable equivocation, ADR-0010 will
  swap `H_r` for a `(c, s)` Schnorr-PoK with the extraction
  property.

### Cross-cutting — constraints on downstream issues

- **#655** MUST implement `wrapper::keygen`, `wrapper::nonce`,
  `wrapper::verify` with the signatures pinned above. `r` MUST be
  returned as a `secp256k1::SecretKey` and MUST NOT cross any FFI
  / serde boundary as a raw scalar. `R` MUST round-trip through
  the 33-byte compressed encoding. `wrapper::verify` MUST be
  constant-time with respect to `π` byte content (the underlying
  ECVRF verify already is, modulo TAI's input-dependent loop —
  which `x` is public, so OK).
- **#655** MUST expose `pub const R_DERIVATION_TAG: &[u8]` set to
  `b"DARK-VON-r-v1"` and `pub const ALPHA_PRIME_LAYOUT: &str` (a
  doc-only constant) noting `x || R_compressed`. These pin the
  wire spec for vectors in #656.
- **#656** uses BIP-340 tagged-hash framing (`H_nonce`), distinct
  from `H_r`. Tag for `H_nonce` is `b"DARK-VON-nonce-input-v1"`
  (matches the `dark-<crate>/<purpose>/v1` convention observed in
  `crates/dark-confidential/src/balance_proof.rs:91-96`). The
  issue text references a `b"DarkRound*"` family in `round_tree.rs`;
  that file does not exist on `main`. We follow the actually-extant
  convention.
- **#656** MUST emit at least one vector covering `b=1` vs `b=2`
  collision check (distinct `H_nonce` outputs ⇒ distinct `R`).
- **#657** uses `wrapper::nonce` for each `(t, b)` pair. The
  `SecretSchedule` retains `r` values; the `PublicSchedule` retains
  `(R, π)` only.
- **#658** measures `wrapper::nonce` and `wrapper::verify`
  separately from `ecvrf::prove` and `ecvrf::verify`, so the
  wrapper overhead is visible. If `wrapper::nonce` median exceeds
  `ecvrf::prove` median by more than ~30 µs (HMAC-SHA-256 of a
  ≤200 B input), reopen this ADR — that would indicate accidental
  recomputation.

## References

- Issue #654 (this ADR).
- Issue #652 — ECVRF surface this wrapper consumes (ADR-0006 pins
  the byte spec).
- Issue #655 — the wrapper implementation.
- Issue #656 — `H_nonce` and VON test vectors.
- Issue #657 — schedule generator built on top of `wrapper`.
- BIP-327 — MuSig2 two-nonce structure.
- RFC 6979 §3.2 — deterministic nonce generation; same primitive
  used inside `ecvrf::nonce_rfc6979` and structurally re-applied
  for `H_r` here.
- ADR-0001 — workspace curve-context invariant honoured by the
  wrapper (no new curve dep).
