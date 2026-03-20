# Security Model & Threat Analysis — dark

> **Scope:** This document covers the dark Ark Service Provider (ASP) implementation.
> It is a living document; update it as the protocol and codebase evolve.

---

## 1. Architecture Overview

dark is a Rust implementation of the Ark protocol ASP (Application Service Provider).
The ASP coordinates off-chain VTXO (Virtual Transaction Output) rounds, manages the
VTXO tree, and facilitates both collaborative and unilateral exits to on-chain Bitcoin.

**Trust model:** The ASP is a semi-trusted coordinator. Users retain unilateral exit
capability — they can always reclaim their funds on-chain without ASP cooperation,
subject to timelock constraints.

---

## 2. Known Attack Vectors

### 2.1 ASP (Operator) Compromise

| Threat | Impact | Mitigation |
|--------|--------|------------|
| ASP key theft | Attacker can co-sign forfeit txs, potentially stealing funds before users exit | HSM/threshold signing for ASP keys (future); key rotation policy |
| ASP goes offline | Users must perform unilateral exits (more expensive) | Timelocks guarantee user can always exit; monitor ASP liveness |
| ASP censors users | Specific users denied round participation | Users fall back to unilateral exit; no funds at risk |
| ASP double-spends | ASP signs conflicting transactions | Connector outputs enforce ordering; forfeit txs penalise ASP |

### 2.2 User Griefing Attacks

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Intent spam | Flood registration with bogus intents to stall rounds | `max_intents` cap (128 default); require auth tokens |
| Large VTXO count | OOM via huge batches | `MAX_VTXO_COUNT` validation (4096); input bounds checks |
| Invalid signatures | Force ASP to waste CPU verifying bad sigs | Early rejection; signature checks before expensive operations |
| Dust outputs | Create un-spendable VTXOs | `MIN_VTXO_AMOUNT_SATS` (546 sats) enforced in `ArkService` |

### 2.3 Timelock Manipulation

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Zero timelock | Immediate spend defeats exit safety | Validated: exit_delta > 0, CLTV > 0, CSV > 0 |
| Excessive timelock | Funds locked beyond useful lifetime | Caps: `MAX_TIMELOCK_BLOCKS` (525,960 ≈ 10yr), CSV max 65535 |
| Timelock type confusion | Mixing block-height and time-based locks | Separate `LockTime::Blocks` / `LockTime::Seconds` validation paths |
| Stale VTXO expiry | User doesn't refresh before expiry, ASP sweeps | `expires_at` tracked; clients should refresh well before deadline |

### 2.4 VTXO Tree Construction Attacks

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Malformed tree | Invalid Taproot tree prevents users from exiting | Tree depth validation (`MAX_TREE_DEPTH` = 32) |
| Duplicate outputs | Same VTXO appears twice, enabling double-spend | Outpoint-based deduplication in VTXO repository |
| Script malleation | Altered scripts in tree nodes | Scripts built deterministically from pubkeys + params; no user-supplied raw scripts |
| Unbalanced tree | Extremely deep paths increase exit cost | Depth cap + balanced construction algorithm |

### 2.5 Network-Level Attacks

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Eclipse attack on ASP | ASP sees stale chain, accepts invalid proofs | Multiple Bitcoin RPC endpoints (configurable) |
| Fee sniping | Attacker front-runs low-fee exits | Fee rate validation (`MIN_FEE_RATE_SAT_VB`); cap at `MAX_FEE_RATE_SAT_VB` |
| Transaction pinning | Malicious counterparty pins commitment tx | Use V3 transaction format when available; CPFP-friendly outputs |

---

## 3. Input Validation Summary

All external inputs are validated before reaching domain logic. See `crates/dark-core/src/validation.rs`.

| Input | Validation |
|-------|-----------|
| Amount (sats) | > 0, ≤ 2,100,000,000,000,000 |
| Public key (hex) | Valid hex, 32-byte (x-only) or 33-byte (compressed), on curve |
| Transaction ID | 64 hex chars |
| VTXO count | > 0, ≤ 4,096 |
| Tree depth | > 0, ≤ 32 |
| Fee rate | ≥ 1, ≤ 100,000 sat/vB |
| Timelock (blocks) | > 0, ≤ 525,960 |
| Exit delay (CSV) | > 0, ≤ 65,535 |
| VTXO exit_delta | > 0, ≤ 65,535; user ≠ ASP pubkey |

---

## 4. Error Handling Policy

- **No `.unwrap()` on user-controlled data.** All external inputs use `Result`-based error handling.
- **`.expect()` is only used for static/compile-time values** (e.g., hard-coded test keys).
- **Panics must not be reachable from external input.** Any panic path from gRPC/API input is a bug.
- **Error messages never leak internal state** (file paths, SQL queries, stack traces).

---

## 5. Dependency Security

Dependencies are audited with `cargo audit` and policy-enforced with `cargo deny` (see `deny.toml`).

### Current Known Issues (as of v0.1.0)

| Advisory | Crate | Severity | Status |
|----------|-------|----------|--------|
| RUSTSEC-2023-0071 | `rsa` (via sqlx-mysql) | Medium | Accepted — MySQL not used; SQLite only |
| RUSTSEC-2025-0141 | `bincode` (via bdk) | Unmaintained | Accepted — upstream migration tracked |
| RUSTSEC-2025-0134 | `rustls-pemfile` (via reqwest) | Unmaintained | Accepted — upstream migration tracked |
| RUSTSEC-2021-0137 | `sodiumoxide` (via macaroon) | Deprecated | Accepted — migration to `libsodium-sys-stable` or `chacha20poly1305` planned |

---

## 6. Cryptographic Considerations

- **Signature scheme:** Schnorr (BIP-340) via `secp256k1` crate — well-audited.
- **Sighash:** All signatures must use `SIGHASH_DEFAULT` (BIP-341) or `SIGHASH_ALL` to prevent input/output manipulation.
- **MuSig2:** Cosigning uses the MuSig2 protocol for aggregated Schnorr signatures. Nonce reuse is fatal — each session generates fresh nonces.
- **Macaroon auth:** Uses `sodiumoxide` for HMAC. The `sodiumoxide` crate is deprecated; migration planned.

---

## 7. Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue.
2. Email the maintainers (see repository contacts).
3. Include: description, reproduction steps, impact assessment.
4. We aim to acknowledge within 48 hours and patch within 7 days for critical issues.
