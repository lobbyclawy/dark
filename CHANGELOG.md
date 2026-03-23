# Changelog

All notable changes to dark will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Architecture documentation (`docs/architecture.md`)
- CHANGELOG.md for tracking releases

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

[Unreleased]: https://github.com/lobbyclawy/dark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lobbyclawy/dark/releases/tag/v0.1.0
