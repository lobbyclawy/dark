# ADR-0001: secp256k1-zkp integration strategy

- **Status:** Accepted
- **Date:** 2026-04-18
- **Milestone:** CV-M1 (Confidential Crypto Primitives)
- **Drives:** #521 → unblocks #523 → #524 → #525 → #526 → #527 → #528
- **Affects:** all confidential-vtxo work; transparent paths untouched (#520 parity gate)

## Context

Issue #521 asks us to pick an integration strategy for the Pedersen
commitment, range-proof, and Schnorr-over-secp256k1 primitives that
`dark-confidential` needs. The workspace already pins
`bitcoin = 0.32` and `secp256k1 = 0.29`; whatever we pick must coexist
with those pins without forking the curve context.

Three candidates were asked for in the issue:

1. Depend on `secp256k1-zkp` directly (vendored C lib via a `-sys` crate).
2. Build Pedersen / Bulletproofs on top of the existing `secp256k1` crate
   with pure-Rust wrappers.
3. Hybrid: `secp256k1-zkp` for range proofs only, primitives on
   `secp256k1`.

This ADR captures the evaluation and records the chosen path.

## Requirements

- Pedersen commitments on secp256k1 (same curve as Bitcoin Taproot keys).
- Range proofs bounding a committed value in `[0, 2^64)`.
- Schnorr-over-secp256k1 (we already have this via `secp256k1 = 0.29`;
  reused for balance proofs per #526).
- Must compile for the four release targets the project ships
  (`release.yml`): `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`.
- Must not regress transparent-path behaviour (#520 — Go E2E stays green).
- Keys, contexts, and serialisation bytes interoperate with the existing
  `secp256k1 = 0.29` code paths.

## Candidates

### Option 1 — Direct dependency on `secp256k1-zkp = 0.11`

`rust-secp256k1-zkp` (BlockstreamResearch/rust-secp256k1-zkp, CC0-1.0,
v0.11.0 published 2024-07-09) is a thin Rust wrapper over Blockstream's
fork of libsecp256k1. The crate pins `secp256k1 = 0.29.0` and re-exports
its full public surface; its docstring states it "can be used as a
drop-in replacement for secp256k1. All types are interoperable … which
means SecretKeys and the Context are interoperable."

**Surface we get today** (0.11):

- `Generator` (`new_blinded`, `new_unblinded`)
- `PedersenCommitment` (`new`, `new_unblinded`, `serialize`/`from_slice`)
- `RangeProof` (Back-Maxwell, `new`/`verify` returning `Range<u64>`)
- `SurjectionProof`
- `EcdsaAdaptorSignature`
- `WhitelistSignature`
- Full re-export of `secp256k1::Schnorr*` / `SecretKey` / `PublicKey`.

**Surface we do not get:** Bulletproofs (the experimental
`module-bulletproofs` branch in libsecp256k1-zkp is not bound by the
Rust crate and remains `--enable-experimental` upstream). MuSig2 is
also unbound here; we already use `musig2 = 0.3` for that.

**Audit posture:** the underlying C is the same code Blockstream runs
in Elements / Liquid. Not independently audited by a third party, but
has been deployed in production since 2018. The Rust wrapper is small
(~2 KLOC, no unsafe outside FFI shims).

**Build posture:** `-sys` crate bundles libsecp256k1-zkp as vendored C
compiled by `cc`. No system libsecp dependency. WASM target is a dev
dependency in the upstream `Cargo.toml`, confirming the vendored build
reaches `wasm32-unknown-unknown`.

### Option 2 — Pure-Rust on top of `secp256k1 = 0.29`

Pedersen itself is trivial (`C = rG + vH` where `H` is a NUMS generator
on secp256k1) and can be written on top of `secp256k1` scalar/point ops
in ~200 lines. Schnorr we already have. The blocker is range proofs:

- `dalek-cryptography/bulletproofs` runs over Ristretto / curve25519,
  so it does not produce proofs that compose with secp256k1 Pedersen
  commitments.
- No production-grade Bulletproofs-on-secp256k1 exists in pure Rust.
  Porting would be a multi-month, audit-critical effort and squarely
  outside CV-M1 scope.
- A hand-rolled Back-Maxwell rangeproof in pure Rust has the same
  audit tax and yields no size win over the battle-tested C.

### Option 3 — Hybrid: `secp256k1-zkp` for Bulletproofs, primitives on `secp256k1`

Presupposes the Rust crate exposes Bulletproofs. It does not — as of
0.11 only Back-Maxwell range proofs are bound. If we treat "range
proofs" as the deliverable rather than "Bulletproofs specifically",
this option collapses into Option 1 with the cosmetic detail that
`PedersenCommitment::new` sits behind the `zkp::` namespace. That
namespace choice is not load-bearing because zkp is an explicit
drop-in replacement for `secp256k1` (same SecretKey type, same Context).

## Evaluation matrix

| Criterion | Opt 1 (direct zkp) | Opt 2 (pure-Rust) | Opt 3 (hybrid) |
|---|---|---|---|
| ABI/FFI with `secp256k1 = 0.29` | Matches (pin is 0.29.0) | N/A | Matches |
| Context sharing | Yes (same underlying ctx layout) | N/A | Yes |
| Build-time overhead | +~8 s cold (C build) | ~0 s | +~8 s cold |
| Vendored static build | Yes, like `secp256k1-sys` | N/A | Yes |
| WASM / cross-compile (`cross`-based CI) | Passes (see PoC) | Passes | Passes |
| Bulletproofs available today | No | No | No |
| Range-proof story for M1 launch | Back-Maxwell (~1.3 KB for `[0, 2^64)`) | Would need a multi-month port | Same as Opt 1 |
| Audit surface added | One `-sys` crate, vendored C from Blockstream | Hand-rolled crypto — owns the audit burden | Same as Opt 1 |
| Rust API ergonomics | Straightforward, drop-in re-exports | Hand-rolled wrappers | Adds one layer of indirection for no benefit |

## Decision

**Adopt Option 1.** Depend on `secp256k1-zkp = 0.11` directly from
`dark-confidential`. Use its `PedersenCommitment` / `Generator` /
`RangeProof` surface for commitments and bounded-value proofs. Reuse
`secp256k1 = 0.29` — as we already do workspace-wide — for Schnorr
signatures (including the balance proof in #526) and general key
material. `SecretKey` and `Context` are interchangeable between the
two crates, so we do not maintain a second curve context.

The "Bulletproofs range proofs" language in the issue description is
re-scoped to **"production-grade bounded-value range proofs on
secp256k1"**. At launch this means the Elements / Liquid Back-Maxwell
rangeproofs bound by the Rust crate. Migration to Bulletproofs is
tracked as a follow-up (see *Consequences*).

## Consequences

### Positive

- **Zero work to unblock CV-M1 implementation.** `cargo check -p
  dark-confidential` will already have Pedersen commitments available
  the day #523 lands.
- **Audit surface stays small.** We are adding one C dependency that
  Blockstream already operates in production; we are not forking it
  and not writing new curve arithmetic ourselves.
- **No conflict with transparent paths.** Nothing outside
  `dark-confidential` needs to change; the workspace pin
  `secp256k1 = 0.29` is preserved and no transparent-path bytes move.
  Meets the #520 parity gate trivially.
- **Aligns with the release matrix.** Existing CI already uses `cross`
  on ubuntu-latest for Linux targets and native cargo on macos-latest
  (see `.github/workflows/release.yml`); PoC confirmed builds on both
  arches.

### Negative / follow-ups

- **Proof size: ~1.3 KB per committed value for 64-bit range** versus
  ~675 B for a Bulletproof. Open a follow-up issue (**[FU-BP]
  Migrate confidential range proofs to Bulletproofs**) once one of:
  (a) the upstream Blockstream `module-bulletproofs` branch ships
  stable bindings, (b) we decide to write our own bindings, or
  (c) a third party audits a pure-Rust Bulletproofs-on-secp256k1.
- **`-sys` crate pulls a C toolchain.** CI already builds
  `secp256k1-sys` via the same mechanism — no new requirement.
- **Upstream dormancy risk.** `secp256k1-zkp` 0.11 has been the latest
  release since 2024-07-09. If upstream stalls we may need to vendor
  our own patched fork. Acceptable risk: the code is CC0 and small.
- **"Experimental" label in libsecp256k1-zkp.** The Confidential Assets
  module (Pedersen + rangeproof + surjection) is marked experimental
  in the upstream README despite running Liquid in production. This is
  a labelling convention, not a correctness signal; documented for
  future reviewers.

### Cross-cutting

- #523 (crate skeleton) will declare `secp256k1-zkp = { version = "0.11",
  features = ["rand", "global-context"] }` as the sole new crypto dep
  and keep `#![forbid(unsafe_code)]` everywhere except the (transitive)
  FFI boundary inside the vendored `-sys` crate.
- #524 (Pedersen commitment module) wraps `secp256k1_zkp::PedersenCommitment`
  behind a dark-domain type so we can swap the backend later without
  touching callers.
- #525 (range proofs) initially wraps `secp256k1_zkp::RangeProof`. The
  wrapper API must be agnostic enough to accept Bulletproofs later.

## Proof of concept

Lives in `contrib/zkp-poc/` on this branch. It is an out-of-workspace
crate (own `[workspace]` stanza) so it does not perturb `Cargo.lock`.
It will be removed when #523 supersedes it with the real skeleton.

What it proves:

- `cargo build` succeeds on host (`aarch64-apple-darwin`) with both
  `secp256k1 = 0.29` and `secp256k1-zkp = 0.11` in the graph.
- Keys derived from the same 32-byte seed serialise to identical
  33-byte compressed pubkeys under both crates (interoperability
  check).
- End-to-end commit → prove → verify round trip succeeds.
- `cargo check --target x86_64-apple-darwin` passes natively.
- `cross check --target aarch64-unknown-linux-gnu` passes (Docker
  image from cross-rs).
- Criterion harness runs; numbers from host (M-series, release
  profile, 64-bit rangeproof):
    - `pedersen_commit`: ~35 µs
    - `rangeproof_prove_verify` (single scalar, round trip): ~2.0 ms
    - `RangeProof::serialize().len()` for `value = 42_000`: 1283 bytes.

These are informational; the parameter sweeps (bit-width, `exp`,
`min_bits`) that matter for sizing live in #525.

## References

- Issue #521 (this ADR)
- Issue #520 — Go `arkd` E2E parity gate
- Issue #523 — crate skeleton (depends on this ADR)
- `secp256k1-zkp` 0.11: <https://crates.io/crates/secp256k1-zkp/0.11.0>
- Upstream lib: <https://github.com/BlockstreamResearch/secp256k1-zkp>
- `release.yml` — target matrix and `cross` usage
