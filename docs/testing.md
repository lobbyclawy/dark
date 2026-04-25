# Testing dark

## Unit Tests

No external dependencies required.

```bash
cargo test --workspace
```

## End-to-End Tests (Nigiri)

### Go `arkd` parity gate

The vendored upstream Go E2E suite at `vendor/arkd/internal/test/e2e` is the
transparent-path compatibility gate for confidential-VTXO work.

The CI decision logic lives in `.github/scripts/go_e2e_gate.py` and is covered
by `.github/scripts/test_go_e2e_gate.py`.

Go E2E runs automatically when any of the following are true:

- the workflow runs on `push`, `schedule`, or `workflow_dispatch`
- a pull request carries the `confidential-vtxos` label
- a pull request touches parity-sensitive surfaces such as `proto/`,
  `crates/dark-api/`, `crates/dark-core/`, `crates/dark-db/migrations/`,
  `crates/dark-live-store/`, `vendor/arkd/`, or `.github/workflows/e2e.yml`

That policy is intentionally conservative. Transparent behaviour must remain
bit-identical while the confidential track lands.

### Prerequisites

- [Nigiri](https://nigiri.vulpem.com/): `curl https://getnigiri.vulpem.com | bash`
- Docker (required by Nigiri)
- grpcurl: `brew install grpcurl`

### Steps

```bash
# 1. Start Nigiri (keep running in background)
nigiri start

# 2. Build the binary (once, or after code changes)
cargo build --release

# 3. Run the e2e script
./scripts/e2e-test.sh
```

### Manual gRPC testing

dark runs on port `7070` (gRPC) and `7071` (admin gRPC).

```bash
# Start dark
cargo run

# In another terminal:
grpcurl -plaintext localhost:7070 list
grpcurl -plaintext localhost:7070 ark.v1.ArkService/GetInfo
grpcurl -plaintext localhost:7070 ark.v1.ArkService/ListRounds

# Admin API
grpcurl -plaintext localhost:7071 ark.v1.AdminService/GetWalletStatus
```
