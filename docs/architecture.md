# dark Architecture

This document explains the architecture of dark, the Rust implementation of the Ark protocol server.

## Overview

dark is a modular, layered system built on hexagonal architecture principles (ports and adapters). The core domain logic is isolated from infrastructure concerns like databases, gRPC, and Bitcoin nodes.

```
                    ┌─────────────────────────────────────────────────────────┐
                    │                    gRPC Layer (dark-api)                │
                    │  ArkService · AdminService · WalletService · Indexer    │
                    └───────────────────────────┬─────────────────────────────┘
                                                │
                    ┌───────────────────────────▼─────────────────────────────┐
                    │                  Application Layer (dark-core)          │
                    │    RoundLoop · RoundExecutor · FraudDetector · Sweeper  │
                    └───────────────────────────┬─────────────────────────────┘
                                                │
         ┌──────────────────────────────────────┼──────────────────────────────────────┐
         │                                      │                                      │
         ▼                                      ▼                                      ▼
┌─────────────────┐                  ┌─────────────────────┐                ┌─────────────────┐
│   dark-bitcoin  │                  │    dark-wallet      │                │   dark-db       │
│  TxBuilder      │                  │  BDK Wallet         │                │  SQLite/Pg      │
│  MuSig2 Signer  │                  │  UTXO Management    │                │  Repositories   │
│  Tapscript      │                  │  Broadcasting       │                │  Migrations     │
└─────────────────┘                  └─────────────────────┘                └─────────────────┘
         │                                      │                                      │
         └──────────────────────────────────────┼──────────────────────────────────────┘
                                                │
                    ┌───────────────────────────▼─────────────────────────────┐
                    │                Supporting Services                      │
                    │  dark-scanner · dark-scheduler · dark-nostr · ...       │
                    └─────────────────────────────────────────────────────────┘
```

## Crate Structure

### Core Crates

| Crate | Purpose |
|-------|---------|
| **dark-core** | Core domain models (Round, VTXO, Intent) and business logic (RoundLoop, RoundExecutor). Defines ports (traits) for infrastructure. |
| **dark-bitcoin** | Bitcoin primitives: PSBT construction, Tapscript (OP_CSV + MuSig2), MuSig2 key aggregation and signing (BIP-327), transaction building. |
| **dark-wallet** | BDK-based operator wallet. UTXO selection, signing, broadcasting, fee estimation. |
| **dark-api** | gRPC server (tonic): ArkService, AdminService, WalletService, IndexerService, SignerManagerService. |

### Infrastructure Crates

| Crate | Purpose |
|-------|---------|
| **dark-db** | Database layer with SQLite and PostgreSQL adapters. Implements VtxoRepository, RoundRepository, and other persistence ports. |
| **dark-live-store** | Ephemeral round state: in-memory or Redis. Stores intents, forfeit txs, signing sessions during round execution. |
| **dark-scanner** | Esplora-based blockchain scanner. Watches for on-chain VTXO spends, triggers fraud detection and sweep scheduling. |
| **dark-scheduler** | Round scheduling: time-based (cron) and block-height-based schedulers. |
| **dark-fee-manager** | Fee estimation: static rates, Bitcoin Core RPC polling, or CEL-based fee programs. |
| **dark-nostr** | Nostr event publisher for VTXO notifications (NIP-01 events). |
| **dark-confidential** | Confidential VTXO primitives and proof scaffolding: commitments, nullifiers, range proofs, balance proofs, stealth addressing, and disclosure helpers. |

### Client Crates

| Crate | Purpose |
|-------|---------|
| **dark-client** | Rust client library for dark gRPC APIs. Used by ark-cli and for testing. |
| **ark-cli** | Command-line client for interacting with a dark server. |

## Key Concepts

### Ports and Adapters

dark-core defines **ports** (traits) for all infrastructure:

```rust
// Port: abstract interface
pub trait VtxoRepository: Send + Sync {
    async fn add_vtxos(&self, vtxos: &[Vtxo]) -> ArkResult<()>;
    async fn get_vtxos(&self, outpoints: &[VtxoOutpoint]) -> ArkResult<Vec<Vtxo>>;
    // ...
}

// Adapter: concrete implementation (in dark-db)
pub struct SqliteVtxoRepository { /* ... */ }
impl VtxoRepository for SqliteVtxoRepository { /* ... */ }
```

This allows swapping implementations (SQLite ↔ PostgreSQL, in-memory ↔ Redis) without changing core logic.

### Domain Models

Core domain types in `dark-core::domain`:

- **Round**: A batched settlement period with registered intents
- **VTXO**: Virtual transaction output (off-chain Bitcoin representation)
- **Intent**: User's request to participate in a round (deposit, transfer, or exit)
- **FlatTxTree**: The VTXO commitment tree (batch transaction + connectors)
- **BoardingInput**: On-chain UTXO being brought into Ark

### Round Lifecycle

```
              ┌─────────────────┐
              │  Registration   │ ← Users register intents (RegisterIntent RPC)
              └────────┬────────┘
                       │ round_duration_secs elapsed
                       ▼
              ┌─────────────────┐
              │  Confirmation   │ ← Users confirm participation (ConfirmRegistration)
              └────────┬────────┘
                       │ tree built, forfeit txs collected
                       ▼
              ┌─────────────────┐
              │  Finalization   │ ← MuSig2 tree signing (nonces → signatures)
              └────────┬────────┘
                       │ all signatures collected
                       ▼
              ┌─────────────────┐
              │   Broadcast     │ ← Commitment tx broadcast to Bitcoin network
              └─────────────────┘
```

### MuSig2 Signing Flow (BIP-327)

1. **Key Aggregation**: Combine all participant pubkeys + server pubkey into aggregate key
2. **Nonce Generation**: Each participant generates and shares nonces
3. **Partial Signing**: Each participant signs with their share
4. **Signature Aggregation**: Server combines partial signatures into Schnorr signature

This happens for every node in the VTXO tree during Finalization phase.

### Fraud Detection

The scanner watches for on-chain VTXO spends:

1. **VTXO Spent On-Chain**: Scanner detects unilateral exit via Tapscript path
2. **Fraud Check**: Compare against known settlements to detect double-spend attempts
3. **Reaction**: Broadcast pre-signed forfeit transaction to claim collateral

### Sweeping

Expired VTXOs and connector outputs are swept back to the operator wallet:

1. **Expired VTXOs**: After `unilateral_exit_delay` (OP_CSV), operator can sweep unclaimed outputs
2. **Connector Outputs**: After round batch expires, connector tree outputs are swept
3. **Batch Processing**: Multiple sweep targets combined into single transaction for efficiency

## Data Flow

### Settlement (Round Participation)

```
Client                          dark                           Bitcoin
  │                               │                               │
  │── RegisterIntent ───────────►│                               │
  │◄─── intent_id ────────────────│                               │
  │                               │                               │
  │── ConfirmRegistration ──────►│                               │
  │◄─── forfeit_txs_to_sign ─────│                               │
  │                               │                               │
  │── SubmitSignedForfeitTxs ───►│                               │
  │                               │                               │
  │◄─ TreeSigningStarted (stream)│                               │
  │── SubmitTreeNonces ─────────►│                               │
  │◄─ TreeNoncesReceived ────────│                               │
  │── SubmitTreeSignatures ─────►│                               │
  │                               │                               │
  │◄─ RoundFinalized (stream) ───│── broadcast_tx ──────────────►│
  │                               │                               │
```

### Off-Chain Transfer

```
Alice                           dark                           Bob
  │                               │                               │
  │── SubmitTx (to Bob) ────────►│                               │
  │                               │◄── FinalizeTx ────────────────│
  │                               │───► VTXO ownership updated    │
  │                               │                               │
```

## Configuration

Configuration is loaded from TOML:

```toml
[server]
grpc_port = 7070
admin_grpc_port = 7071

[ark]
network = "regtest"
round_duration_secs = 60
unilateral_exit_delay = 1008    # blocks (OP_CSV)
boarding_descriptor_template = "..."

[deployment]
mode = "light"  # or "full"

[esplora]
url = "http://localhost:3000"
```

See `config.example.toml` for full documentation.

## Deployment Modes

### Light Mode

- **Database**: SQLite (embedded)
- **Live Store**: In-memory
- **External Deps**: None
- **Use Case**: Development, testnet, small mainnet deployments

### Full Mode

- **Database**: PostgreSQL
- **Live Store**: Redis
- **External Deps**: PostgreSQL server, Redis server
- **Use Case**: Production mainnet deployments

## Security Architecture

### Key Isolation

The signer can run as a separate process (`dark-signer` binary) for key isolation. Communication is via gRPC with mutual TLS.

### Authentication

- **Macaroons**: Bearer tokens with capability-based permissions
- **TLS**: Auto-generated or user-provided certificates for gRPC endpoints

### Network Security

- All gRPC endpoints support TLS
- Admin API runs on separate port (7071) for firewall isolation
- Intent proofs use BIP-322 message signing for ownership verification

## Observability

### Metrics (Prometheus)

dark exposes metrics on `/metrics`:

- `dark_rounds_total`: Total rounds executed
- `dark_vtxos_created`: Total VTXOs created
- `dark_round_duration_seconds`: Round execution time histogram

### Tracing (OpenTelemetry)

Distributed tracing via OpenTelemetry. Configure with:

```toml
[telemetry]
enabled = true
otlp_endpoint = "http://localhost:4317"
```

### Logging

Structured JSON logging (tracing-subscriber) with configurable levels:

```bash
RUST_LOG=dark=debug,dark_core=trace cargo run
```

## Further Reading

- [Ark Protocol Whitepaper](https://arkpill.me)
- [Testing Guide](testing.md)
- [Operational Runbook](runbook.md)
- [Light Mode Deployment](light-mode.md)
