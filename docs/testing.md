# Testing arkd-rs

## Unit Tests

```bash
cargo test --workspace
```

## Integration Tests (Nigiri)

### Prerequisites

- [Nigiri](https://nigiri.vulpem.com/) installed
- grpcurl installed (optional but recommended)

### Setup

```bash
nigiri start
./scripts/e2e-test.sh
```

### Manual gRPC testing

```bash
# Start arkd
cargo run

# In another terminal:
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext localhost:50051 ark.v1.ArkService/GetInfo
grpcurl -plaintext localhost:50051 ark.v1.ArkService/ListRounds
```
