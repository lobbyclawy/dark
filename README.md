# arkd-rs

**Rust implementation of [arkd](https://github.com/arkade-os/arkd)** - Ark protocol server for Bitcoin Layer 2 scaling.

⚠️ **EXPERIMENTAL** - This is a ground-up Rust rewrite. Not production-ready.

---

## What is arkd?

arkd is a server implementation of the **Ark protocol**, a Bitcoin scaling solution that enables:

- ✅ Fast, low-cost off-chain transactions
- ✅ Bitcoin security guarantees maintained
- ✅ Batched settlements on-chain
- ✅ User custody always preserved

**Original (Go):** https://github.com/arkade-os/arkd  
**This project:** Rust rewrite for performance, safety, and modern Bitcoin infrastructure.

---

## Why Rust?

**Advantages over the Go implementation:**

- 🦀 **Memory safety** - No null pointers, data races prevented at compile-time
- ⚡ **Performance** - Zero-cost abstractions, faster execution
- 🔒 **Security** - Type system catches bugs early, ideal for Bitcoin infra
- 🛠️ **Ecosystem** - Native Bitcoin libs (rust-bitcoin, BDK), excellent async (tokio)
- 📦 **Modern tooling** - Cargo, robust testing, easy dependency management

---

## Project Structure

```
arkd-rs/
├── crates/
│   ├── arkd-core/        # Core business logic (rounds, VTXOs, batching)
│   ├── arkd-wallet/      # Bitcoin wallet integration (liquidity provider)
│   ├── arkd-api/         # gRPC/REST API (tonic + prost)
│   ├── arkd-db/          # Database layer (Postgres, SQLite, Redis)
│   └── arkd-bitcoin/     # Bitcoin primitives (transactions, scripts)
├── src/
│   └── main.rs           # Server binary entry point
├── proto/                # Protocol Buffer definitions
├── migrations/           # Database migrations
├── tests/                # Integration tests
└── Cargo.toml            # Workspace configuration
```

**Architecture mirrors original arkd:**
- `crates/arkd-core` → `internal/core/application`
- `crates/arkd-wallet` → `pkg/arkd-wallet`
- `crates/arkd-api` → `internal/interface/grpc`
- `crates/arkd-db` → `internal/infrastructure/db`

---

## Features (Planned)

### Phase 1: Core Infrastructure ✅
- [x] Project structure
- [x] Bitcoin primitives (UTXO, transactions, scripts)
- [x] Database layer (Postgres + SQLite)
- [ ] Configuration system
- [ ] Logging & telemetry

### Phase 2: Wallet & Liquidity ✅
- [x] On-chain wallet (BDK integration)
- [ ] NBXplorer client (compatibility with original)
- [ ] Signing service
- [ ] UTXO management

### Phase 3: Ark Protocol ✅
- [x] VTXO tree construction
- [x] Round management (batching logic)
- [x] Collaborative exit
- [x] Unilateral exit
- [x] Boarding transactions

### Phase 4: API
- [ ] gRPC server (tonic)
- [ ] REST gateway
- [ ] Admin API
- [ ] Client SDK (Rust)

### Phase 5: Production Readiness
- [ ] Comprehensive testing (unit + integration)
- [ ] Performance benchmarks
- [ ] Security audit
- [ ] Docker deployment
- [ ] Monitoring & alerts

---

## Quick Start

### Prerequisites

- **Rust** 1.75+ (install: https://rustup.rs/)
- **Bitcoin Core** or **Nigiri** (for regtest)
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
# Unit tests
cargo test --lib

# Integration tests (requires Bitcoin regtest)
cargo test --test '*'

# Benchmarks
cargo bench
```

### Code style

```bash
# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings
```

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

## Roadmap

**2026 Q2:**
- ✅ Repository setup
- ✅ Core crate structure
- 🔄 Bitcoin primitives
- 🔄 Database layer

**2026 Q3:**
- Wallet integration
- Ark protocol core
- gRPC API

**2026 Q4:**
- Testnet deployment
- Security audit
- Documentation

---

## Contributing

This is a **private research project** during initial development.

**Guidelines:**
- Follow Rust best practices (use `clippy`, `rustfmt`)
- Write tests for new features
- Document public APIs
- Sign your commits (GPG)

---

## Resources

**Original arkd (Go):**
- Repo: https://github.com/arkade-os/arkd
- Docs: https://deepwiki.com/arkade-os/arkd

**Ark Protocol:**
- Spec: https://ark-protocol.org/
- Paper: [Ark: An Alternative to Lightning](https://github.com/ark-protocol/ark-spec)

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
