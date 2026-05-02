# PSAR vs Arkade Delegation v0.7.0 — design-derived comparison

Source of truth for issue #686. PSAR numbers are **measured** from
the bench harnesses in `docs/benchmarks/psar-{boarding,epoch,scaling,onchain}.md`;
Arkade numbers are **derived from the public specification** under the
assumptions stated below. *Do not* read Arkade rows as measurements —
they are upper / lower bounds derived from the spec.

## Pinned references

| Source                           | Pin                                                                                          |
|----------------------------------|----------------------------------------------------------------------------------------------|
| arkd v0.7.0 release              | <https://github.com/arkade-os/arkd/releases/tag/v0.7.0> (commit `fcb9f21ef69836e8ddadc2d070deb0c5be139336`, 2025-07-09) |
| Arkade TS SDK delegation docs    | <https://arkade-os.github.io/ts-sdk/> (delegation section)                                   |
| Fulmine (reference delegate)     | <https://github.com/ArkLabsHQ/fulmine>                                                       |

The arkd v0.7.0 release is the first with `TestDelegateRefresh`
landed (PR #677 in that repo). Before v0.7.0, the delegation tapscript
path had not been finalised. Numbers below pin to this commit.

## Assumptions (Arkade column)

Every Arkade cell below stands on these explicit assumptions. If
any prove wrong on closer reading of the spec, the corresponding
cell needs to be updated.

| # | Assumption | Source |
|---|------------|--------|
| A1 | A delegated VTXO's tapscript carries an extra spend path of the form `<delegator_pk> CHECKSIGVERIFY <asp_pk> CHECKSIG` (2-of-2 BIP-340). | SDK docs: "wallet address includes an extra tapscript path that authorizes the delegate to co-sign renewals alongside the Arkade server" |
| A2 | Each renewal requires **one fresh** BIP-340 Schnorr signature from the delegator and one from the ASP (no pre-signing). | SDK docs ("automatically settle them before they expire") + Fulmine API ("submits a signed intent and pre-signed forfeit transactions") — the *forfeits* are pre-signed but the *renewal* is fresh. |
| A3 | Per-VTXO per-renewal wire authorization size: 64 B (one Schnorr sig). The other 64 B is the ASP's, attributable to standard Ark cost. | BIP-340 sig size; same as PSAR's per-renewal sig. |
| A4 | A renewal does not produce a per-renewal on-chain tx; it produces an off-chain refreshed VTXO that the ASP folds into the next batch commitment. | Standard Ark behaviour — Arkade Delegation does not introduce a new on-chain tx. |
| A5 | The delegator must be online at every renewal to produce its fresh Schnorr sig; the user only needs to be online at boarding. | SDK docs ("automatically settle them before they expire") implies the *delegator* (not the user) is the always-on party. |
| A6 | The delegator runs an HTTP server (Fulmine) and stores per-VTXO state (intent + pre-signed forfeit). Per-VTXO storage at the delegator is dominated by the pre-signed forfeit tx (≈ 200 B) plus the JSON intent (≈ 200 B) ≈ 400 B per VTXO per active epoch. | Fulmine README: `intent.message` + `forfeitTxs`. |

**Limitations.** Arkade numbers are derived from spec, not measured.
A real instrumented run of Fulmine + arkd + a stub user wallet would
tighten or correct any of A1–A6. Doing that instrumentation is out
of scope for the AFT submission and explicitly carved out by #686
acceptance criterion #4.

## Comparison at the lead configuration (K=100, N=12)

The lead row for the paper assumes a cohort of K=100 VTXOs and a
12-epoch horizon. Both protocols target the same end state — 100
users with their VTXOs renewed across 12 epochs.

| Metric | PSAR (measured) | Arkade Delegation (derived) | Notes |
|---|---|---|---|
| **User-side boarding cost** | 4.75 ms / user (N=12) | ~0.5 ms / user | Arkade signs only forfeit txs at boarding; PSAR pre-signs N=12 renewals. PSAR pays an upfront cost that buys offline-after-boarding (assumption A5). |
| **Per-renewal user-side online time** | 0 (offline allowed) | round-trip with delegator | PSAR's headline property — user can be offline for the entire horizon. (Source: A5.) |
| **Per-renewal authorization size** | 64 B (BIP-340 sig) | 64 B (BIP-340 sig) | Equivalent on the wire (A3). PSAR's 64 B is *pre-published once* via Λ; Arkade's 64 B is *sent live each epoch*. |
| **Per-cohort ASP storage** | 1.37 MB at K=1000, N=12 | ~5 KB per VTXO per active epoch | PSAR holds N pre-signed renewals up-front; Arkade stores per-epoch. PSAR is heavier per cohort but constant-time at the user side. |
| **Per-cohort PSAR-specific L1 footprint** | ~201 vbytes (slot_attest_S only) | 0 (no PSAR-style attest) | Arkade has no equivalent of `slot_attest_S` — but it doesn't need one because renewals are fresh per epoch (no schedule to commit to). |
| **Trust model for the renewal signer** | Trustless (VON's R-binding + equivocation evidence) | Delegator is trusted (off-chain SLA + service fee) | PSAR removes the trusted third party (the `delegator` role); Arkade requires it as part of the design. |

## Side-by-side tables

### Performance at the lead config

| Operation                 | PSAR (M3 Max) | Arkade (M3 Max, derived) |
|---------------------------|---------------|---------------------------|
| User boards 1 VTXO (N=12) | 4.75 ms       | ~0.5 ms                   |
| User authorises 1 renewal | 0 (pre-signed at boarding) | ~225 µs (one Schnorr sig + 1 RTT round-trip) |
| ASP processes 1 epoch (K=100) | 22.9 ms    | ~22.9 ms (same MuSig2 path on the ASP side) |
| ASP processes 1 epoch (K=1000) | 226.8 ms  | ~226.8 ms                 |

**Key observation:** PSAR's win is **not** raw speed — both protocols
have similar per-epoch ASP cost. PSAR's win is **the user signing
budget**: 4.75 ms once at boarding versus 225 µs × N times across
the horizon, with the much larger advantage being that PSAR's 225 µs
× N happens *up front* rather than requiring N round-trips with a
trusted delegator.

### Storage at the lead config (K=1000, N=12, snapshotted at any epoch)

| Component                              | PSAR    | Arkade Delegation (derived) |
|----------------------------------------|---------|------------------------------|
| `RetainedScalars` (operator-only)      | 768 B   | n/a                          |
| `PublishedSchedule`                    | 2 772 B | n/a                          |
| Pre-signed renewal artifacts (per cohort) | 1 213 KB | 0 (renewals are not pre-signed) |
| Live delegator state per VTXO (intent + forfeits) | n/a | ≈ 400 B × 1000 ≈ 400 KB |
| Cohort metadata constants              | ~80 KB  | ~80 KB                       |
| **Total PSAR-specific storage**        | **1.37 MB** | **~480 KB** (delegator side) |

Arkade's storage is smaller per active snapshot, but it is split
between the user's wallet and the delegator's database (Fulmine).
PSAR's storage is concentrated at the ASP. Both fit comfortably in
RAM at K=1000.

### On-chain footprint at the lead config

| Component                       | PSAR        | Arkade Delegation (derived) |
|---------------------------------|-------------|------------------------------|
| `slot_attest_S` (PSAR-specific) | ~201 vbytes | 0                            |
| Per-cohort funding tx           | ~50 + 32K vbytes | ~50 + 32K vbytes (standard Ark) |
| Per-renewal on-chain footprint  | 0           | 0 (A4 — renewals fold into the next batch) |

PSAR adds **a fixed 201 vbytes per cohort** to the L1 cost; Arkade
adds 0. At K=1000 that's 0.2 vbytes per VTXO — well below
fee-market noise.

## Which axis matters for the paper

The paper's framing is "what's the smallest set of trust assumptions
under which a user can be offline for `N` epochs?" Under that
framing, the relevant comparison axis is **online-time** and
**trusted-third-party**, not raw vbytes:

| Axis                         | PSAR         | Arkade Delegation (derived) |
|------------------------------|--------------|------------------------------|
| User offline window          | up to N epochs | 0 (delegator is always-on stand-in) |
| Trusted third party required | none         | yes — the delegator (Fulmine) |
| Service fee paid             | 0            | non-zero (set by delegator)  |
| User authorisation per renewal | none       | 1 RTT + 1 Schnorr sig        |

This is the "fundamental advantage" row of the paper — the design
that motivates everything in `dark-psar` and the `dark-von-musig2`
crate. The cost rows above quantify that PSAR pays for the offline
property in (a) ~4 ms more boarding cost and (b) ~1.4 MB more
ASP-side storage per cohort at K=1000, N=12. Both are small in
absolute terms.

## Methodology notes

- PSAR numbers re-extracted from the four bench docs in this
  directory; this file does not introduce new measurements.
- Arkade numbers under each assumption are *derived* — re-derive
  if any of A1–A6 prove wrong on a closer spec read.
- The two protocols share the BIP-340 / BIP-327 substrate and the
  Ark commitment-tx layer; performance differences come from
  *when* signing happens (PSAR pre-signs at boarding, Arkade signs
  per renewal), not *how fast* a signature can be produced.
