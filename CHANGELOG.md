# Changelog

All notable changes to dark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-04-27

This release ships the **Confidential VTXO** subsystem on top of the v0.1.0 transparent baseline, completes the workspace split into focused crates, and brings the regtest suite to full Go-arkd E2E parity.

### Added

#### Confidential VTXO subsystem
- New `dark-confidential` crate: secp256k1 Pedersen commitments, Back-Maxwell range proofs (via `secp256k1-zkp`), Schnorr balance proofs, deterministic nullifier derivation, stealth addressing, viewing-key issuance with scoped access, and selective-disclosure helpers
- `Vtxo::Confidential` domain variant in `dark-core` carrying commitment, range proof, owner / ephemeral pubkeys, encrypted memo, and nullifier
- Additive `proto/ark/v1/confidential.proto` — `ConfidentialVtxo` payload behind a `vtxo_body` oneof on `Vtxo` and `IndexerVtxo`, with reserved field-number ranges for future extensions
- SQLite + PostgreSQL migrations for confidential columns alongside the transparent rows; indexed nullifier lookups for VTXO resolution
- Real Bitcoin tapscript builder for confidential VTXO unilateral exits; gRPC validator wired through the API path with dynamic `FeeManagerService`

#### Confidential client + CLI
- `dark-client` confidential transaction builder, encrypted local cache for owned confidential VTXOs, deterministic blinding derivation from seed, ChaCha20-Poly1305 memo AEAD per ADR-0003
- Wallet restore with stealth VTXO re-scan
- `ark-cli` confidential `send` / `receive` / `scan` commands; stealth-address commands; `disclose` / `verify` selective-disclosure commands
- Confidential-aware balance and history

#### Compliance and selective disclosure
- VTXO selective reveal with commitment opening
- Source-of-funds proofs over the linkable commitment graph
- Bounded-range compliance proofs
- `VerifyComplianceProof` gRPC endpoint on `dark-api`
- Real CBOR bundle codec and proof verifiers wired through the API

#### New workspace crates
- `dark-client` — gRPC client library
- `dark-confidential` — confidential VTXO primitives
- `dark-fee-manager` — fee estimation (static + Bitcoin Core RPC + CEL programs)
- `dark-live-store` — ephemeral round state (in-memory + Redis)
- `dark-nostr` — Nostr event publishing for VTXO notifications
- `dark-rest-client` — HTTP client for the REST wallet surface
- `dark-scanner` — Esplora blockchain scanner for on-chain VTXO watching
- `dark-scheduler` — time-based and block-height-based round schedulers
- `dark-signer` — remote-signer crate (key isolation over gRPC)
- `dark-wallet-bin` — standalone wallet binary entrypoint
- `dark-wallet-rest` — REST + SSE wallet daemon
- `ark-cli` — command-line client (transparent + confidential)

#### Documentation
- ADR-0001: secp256k1-zkp integration strategy
- ADR-0002: nullifier derivation scheme
- ADR-0003: confidential VTXO memo format and encryption scheme
- ADR-0004: confidential fee handling
- ADR-0005: confidential exit script
- M5/M6 design docs: stealth derivation, announcement pruning, viewing-key scope, disclosure types, compliance bundle format
- SDK integrator guide for confidential transactions
- Migration guide: transparent → confidential
- Confidential threat model
- Selective-disclosure compliance guide (MiCA, FATF Travel Rule, GENIUS Act)
- Source-of-funds proofs reference
- Confidential VTXO protobuf schema reference
- Confidential validation errors observability guide
- Confidential primitives benchmarks baseline
- REST API reference
- Workspace conventions (async, errors, repositories, tracing, null objects)

#### Testing
- Property-based test suite for every confidential primitive
- Criterion benchmarks for Pedersen commitments, range proofs, balance proofs, and nullifiers
- End-to-end regtest tests covering confidential + compliance + exit flows
- 3-way sharded Rust E2E suite (rust-cache)
- 3-way sharded Go E2E suite by measured runtime
- `poll_until` helper with deadline-clamp guard

### Changed
- **Renamed `arkd-*` crates to `dark-*`** across the workspace (#306); repository renamed `arkd-rs` → `dark` (#485)
- Migrated TLS stack to `rustls-tls` across the workspace (#508)
- Use ASP key-path Taproot for connector and forfeit scripts (#481)
- Use per-node cosigners as `TreeTxReady` topic, eliminating Go client nonce patch (#460)
- Apply CPFP child to graph after forfeit broadcast
- Trim broadcast critical-path latency to fit Go E2E budget

### Fixed
- Full Go E2E parity: all 48 Go E2E tests passing (#488)
- Proper PSBT finalization and fee estimation (#478)
- Build and broadcast commitment transaction in round scheduler (#476)
- Checkpoint tx broadcast and exit delay verification (#473)
- Sweep transaction building and broadcast (#475)
- Forfeit transaction structure validation in cosigning (#477)
- Boarding UTXOs included in `send_offchain` coin selection (#474)
- VTXO tree amount validation
- MuSig2 key aggregation pubkey parity preserved
- Indexed `find_by_nullifier` for VTXO resolver

### Security
- Wired real confidential-tx validator into gRPC handler
- Stealth scan transcript aligned between sender and recipient
- Real ViewingKeyIssuance proof type and verifier
- Real ChaCha20-Poly1305 AEAD for memo encryption per ADR-0003

## [0.1.0] - 2026-03-21

### Added

#### Core Protocol
- Full Ark protocol implementation: VTXO tree construction, round management, MuSig2 signing (BIP-327)
- 4-phase round lifecycle: Registration → Confirmation → Finalization → Broadcast
- Fraud detection and forfeit transaction broadcasting
- Collaborative and unilateral exit mechanisms
- Boarding (on-chain → off-chain) support
- Off-chain VTXO transfers (SubmitTx/FinalizeTx)

#### gRPC Services
- **ArkService**: GetInfo, RegisterIntent, ConfirmRegistration, SubmitSignedForfeitTxs, SubmitTreeNonces, SubmitTreeSignatures, GetEventStream, and more
- **AdminService**: Wallet management, sweep controls, round scheduling, fee configuration
- **WalletService**: GenSeed, Create, Restore, Lock/Unlock, GetBalance, Withdraw
- **IndexerService**: VTXO queries, round history, transaction lookups
- **SignerManagerService**: Remote signer registration and health checks

#### Infrastructure
- Hexagonal architecture with ports and adapters
- SQLite and PostgreSQL database backends
- In-memory and Redis live-store for ephemeral state
- Esplora blockchain scanner for on-chain monitoring
- BDK-based operator wallet with full UTXO management
- Time-based and block-height-based round schedulers
- CEL-based fee programs

#### Security
- Macaroon-based authentication with capability scopes
- TLS support with auto-generated or user-provided certificates
- BIP-322 message signing for intent proof verification
- Tapscript VTXO tree with OP_CSV + MuSig2 leaves

#### Observability
- OpenTelemetry tracing integration
- Prometheus metrics endpoint
- Structured JSON logging

#### Deployment
- Light mode (SQLite + in-memory, no external deps)
- Full mode (PostgreSQL + Redis)
- Docker images (dev and distroless production)
- Docker Compose configurations for all deployment modes
- systemd service unit and install script

#### Client SDK
- **dark-client**: Full Rust client library for dark APIs
- **ark-cli**: Command-line interface for testing and operations

#### CI/CD
- GitHub Actions workflows for testing, linting, and releases
- Cross-platform binary releases (Linux amd64/arm64, macOS)
- Docker image publishing to GHCR
- Trivy container security scanning
- buf proto linting
- E2E regtest integration tests with nigiri

### Changed
- Renamed from arkd-rs to dark (#306)

### Security
- Implemented forfeit transaction verification
- Added ban/conviction system for misbehaving participants
- Integrated fraud detection with automatic reaction

---

## Comparison with Go arkd

dark is a full behavioral-parity Rust reimplementation of the [Go arkd](https://github.com/arkade-os/arkd) server. Key differences:

| Aspect | Go arkd | dark (Rust) |
|--------|---------|-------------|
| Memory safety | Runtime checks | Compile-time guarantees |
| Performance | GC pauses possible | Zero-GC, deterministic |
| Bitcoin libraries | btcd/btcsuite | rust-bitcoin, BDK |
| Async model | Goroutines | tokio async/await |
| Binary | Dynamic linking | Single static binary |

[Unreleased]: https://github.com/lobbyclawy/dark/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/lobbyclawy/dark/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lobbyclawy/dark/releases/tag/v0.1.0
