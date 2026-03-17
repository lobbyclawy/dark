# arkd-rs

**Rust implementation of [arkd](https://github.com/arkade-os/arkd) by the [Arkade team](https://github.com/arkade-os)** — Ark protocol server for Bitcoin Layer 2 scaling.

---

## What is arkd?

arkd is a server implementation of the **Ark protocol**, a Bitcoin scaling solution that enables fast, low-cost off-chain Bitcoin transactions with on-chain security guarantees.

---

## Why Rust?

**Advantages over the Go implementation:**

- 🔒 **Memory safety at compile time** — no null pointers, no data races, no memory leaks without `unsafe`
- ⚡ **Deterministic, zero-GC performance** — no garbage collector pauses during round finalization or signing sessions
- 🛠️ **Native Bitcoin ecosystem** — `rust-bitcoin`, `BDK`, `secp256k1` are first-class; Go relies on `btcd` ports
- 🔐 **Stronger type system** — protocol invariants encoded in types, not just documentation
- 📦 **Single static binary** — no runtime dependencies, simpler deployment than Go's dynamic linking

---

## What's Implemented

arkd-rs is a full behavioral-parity Rust reimplementation of the Go arkd server. It covers the complete Ark protocol: VTXO tree construction, round management, MuSig2 signing (BIP-327), fraud detection, forfeit verification (Tapscript), SQLite persistence, Esplora scanning, gRPC API (ArkService + AdminService + WalletService + IndexerService), config hot-reload, and a regtest E2E integration test suite.

---

## Project Structure

```
arkd-rs/
├── crates/
│   ├── arkd-core/        # Core business logic (rounds, VTXOs, batching)
│   ├── arkd-wallet/      # Bitcoin wallet integration (liquidity provider)
│   ├── arkd-api/         # gRPC/REST API (tonic + prost)
│   ├── arkd-db/          # Database layer (Postgres, SQLite, Redis)
│   ├── arkd-bitcoin/     # Bitcoin primitives (transactions, scripts)
│   ├── arkd-nostr/       # Nostr event publishing
│   ├── arkd-client/      # Client SDK crate
│   └── ark-cli/          # Command-line client
├── src/
│   └── main.rs           # Server binary entry point
├── proto/                # Protocol Buffer definitions
├── migrations/           # Database migrations
├── tests/                # Integration tests
└── Cargo.toml            # Workspace configuration
```

---
---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (install: https://rustup.rs/)
- **Nigiri** (Bitcoin regtest + Esplora): `curl https://getnigiri.vulpem.com | bash`
- **grpcurl** (for API testing): `brew install grpcurl`
- **Docker** (required by Nigiri)
- **PostgreSQL** (optional, can use SQLite)
- **Redis** (optional, can use in-memory cache)

### Installation

```bash
# Clone the repo
git clone https://github.com/lobbyclawy/arkd-rs.git
cd arkd-rs

# Build
cargo build --release

# Run tests
cargo test

# Run the server (dev mode)
cargo run -- --network regtest --config config.toml
```

### Configuration

Create `config.toml`:

```toml
[server]
port = 7070
admin_port = 7071

[bitcoin]
network = "regtest"
rpc_url = "http://localhost:18443"
rpc_user = "bitcoin"
rpc_password = "bitcoin"

[database]
type = "postgres"  # or "sqlite"
url = "postgres://user:pass@localhost/arkd"

[cache]
type = "redis"  # or "inmemory"
url = "redis://localhost:6379"

[ark]
vtxo_expiry_seconds = 604800  # 7 days
unilateral_exit_delay = 86400  # 24 hours
round_max_participants = 128
```

---

## Development

### Running locally

```bash
# Start Nigiri (Bitcoin regtest + explorer)
nigiri start

# Run arkd-rs
cargo run

# In another terminal, test the API
grpcurl -plaintext localhost:7070 list
```

### Testing

```bash
# Unit + integration tests (no external dependencies)
cargo test --workspace
```

### End-to-End Tests (Nigiri)

Requires: `nigiri`, `docker`, `grpcurl`

```bash
# 1. Start Nigiri (keep running in background)
nigiri start

# 2. Build the binary (once, or after code changes)
cargo build --release

# 3. Run the e2e test
./scripts/e2e-test.sh
```

The script starts arkd, hits `GetInfo` via gRPC, and cleans up on exit.

---

## Comparison: Go vs Rust

| Feature | arkd (Go) | arkd-rs (Rust) |
|---------|-----------|----------------|
| Language | Go 1.23+ | Rust 1.75+ |
| Bitcoin lib | btcd, btcsuite | rust-bitcoin, BDK |
| gRPC | google.golang.org/grpc | tonic + prost |
| Database | sqlc | sqlx |
| Async runtime | goroutines | tokio |
| Performance | ~Good | **Excellent** |
| Memory safety | Runtime checks | **Compile-time** |
| Ecosystem | Mature | **Growing fast** |

---

## Resources

**Original arkd (Go):**
- Repo: https://github.com/arkade-os/arkd
- Docs: https://deepwiki.com/arkade-os/arkd

**Ark Protocol:**
- Spec: https://ark-protocol.org/

**Rust Bitcoin:**
- rust-bitcoin: https://github.com/rust-bitcoin/rust-bitcoin
- BDK: https://bitcoindevkit.org/

---

## License

MIT (same as original arkd)

---

## Authors

- **Lobby** (lobbyclawy@gmail.com) - Rust implementation
- **Andrea Carotti** (ac.carotti@gmail.com) - Core contributor

Based on [arkd](https://github.com/arkade-os/arkd) by Arkade team.
