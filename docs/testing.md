# Testing arkd-rs

## Unit Tests

No external dependencies required.

```bash
cargo test --workspace
```

## End-to-End Tests (Nigiri)

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

arkd runs on port `7070` (gRPC) and `7071` (admin gRPC).

```bash
# Start arkd
cargo run

# In another terminal:
grpcurl -plaintext localhost:7070 list
grpcurl -plaintext localhost:7070 ark.v1.ArkService/GetInfo
grpcurl -plaintext localhost:7070 ark.v1.ArkService/ListRounds

# Admin API
grpcurl -plaintext localhost:7071 ark.v1.AdminService/GetWalletStatus
```
