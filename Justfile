# dark Justfile
# Run `just --list` to see available commands

# Default recipe
default:
    @just --list

# =============================================================================
# Development
# =============================================================================

# Run cargo check
check:
    cargo check --all-targets --all-features

# Run tests
test:
    cargo test --all-features --workspace

# Run tests with output
test-verbose:
    cargo test --all-features --workspace -- --nocapture

# Run test coverage (requires cargo-tarpaulin: cargo install cargo-tarpaulin)
test-coverage:
    cargo tarpaulin --all-features --workspace --out Html --output-dir coverage

# Run clippy linter
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Build debug
build:
    cargo build

# Build release
build-release:
    cargo build --release

# Run the server (debug)
run *args:
    cargo run -- {{args}}

# Run with custom config
run-config config:
    cargo run -- --config {{config}}

# =============================================================================
# Documentation
# =============================================================================

# Build documentation
doc:
    cargo doc --no-deps --all-features --workspace

# Build and open documentation
doc-open:
    cargo doc --no-deps --all-features --workspace --open

# =============================================================================
# Docker
# =============================================================================

# Start development environment
docker-up:
    docker-compose up -d

# Stop development environment
docker-down:
    docker-compose down

# View logs
docker-logs service="":
    docker-compose logs -f {{service}}

# Start with Esplora
docker-up-esplora:
    docker-compose --profile esplora up -d

# Reset all data (destructive!)
docker-reset:
    docker-compose down -v
    docker-compose up -d

# =============================================================================
# Bitcoin (regtest)
# =============================================================================

# Generate blocks
btc-generate blocks="1":
    docker exec dark-bitcoin bitcoin-cli -regtest -rpcuser=dark -rpcpassword=dark generatetoaddress {{blocks}} $(docker exec dark-bitcoin bitcoin-cli -regtest -rpcuser=dark -rpcpassword=dark getnewaddress)

# Get blockchain info
btc-info:
    docker exec dark-bitcoin bitcoin-cli -regtest -rpcuser=dark -rpcpassword=dark getblockchaininfo

# Get wallet balance
btc-balance:
    docker exec dark-bitcoin bitcoin-cli -regtest -rpcuser=dark -rpcpassword=dark getbalance

# =============================================================================
# Database
# =============================================================================

# Run migrations
db-migrate:
    sqlx migrate run --source migrations

# Create new migration
db-migration name:
    sqlx migrate add {{name}}

# Reset database
db-reset:
    sqlx database reset -y

# =============================================================================
# Security
# =============================================================================

# Run cargo audit
audit:
    cargo audit

# Check licenses and security
deny:
    cargo deny check

# Check for unsafe code
geiger:
    cargo geiger --all-features --all-targets

# =============================================================================
# CI
# =============================================================================

# Run all CI checks
ci: fmt-check lint test doc
    @echo "✓ All CI checks passed"

# Pre-commit hook
pre-commit: fmt lint test
    @echo "✓ Ready to commit"

# =============================================================================
# Utilities
# =============================================================================

# Clean build artifacts
clean:
    cargo clean

# Update dependencies
update:
    cargo update

# Show outdated dependencies
outdated:
    cargo outdated

# Count lines of code
loc:
    @find src crates -name '*.rs' | xargs wc -l | tail -1

# Watch for changes and run tests
watch:
    cargo watch -x test

# =============================================================================
# E2E / Integration
# =============================================================================

# Run E2E regtest suite.
# Always resets Nigiri blockchain state before starting — this prevents
# chopsticks from crash-looping when the chain grows too long for its rescan timeout.
e2e *args: build
    @echo "→ Stopping Nigiri and clearing blockchain state..."
    nigiri stop || true
    @bash -c 'DATADIR="${HOME}/Library/Application Support/Nigiri"; rm -rf "${DATADIR}/volumes/bitcoin/regtest" "${DATADIR}/volumes/electrs" && echo "  ✅ Blockchain data cleared (fresh regtest)"'
    nigiri start
    @echo "⏳ Waiting for Esplora (chopsticks:3000) to be ready..."
    @bash -c 'for i in $(seq 1 180); do h=$(curl -sf http://localhost:3000/blocks/tip/height 2>/dev/null); echo "$h" | grep -qE "^[0-9]+$" && echo "✅ Esplora ready (block $h)" && exit 0; if [ $((i % 15)) -eq 0 ]; then exited=$(docker ps -a --filter name=chopsticks --filter status=exited -q 2>/dev/null); if [ -n "$exited" ]; then echo "  ⚠️  chopsticks crashed — restarting..."; docker restart chopsticks 2>/dev/null || true; fi; fi; echo "  waiting... ($i/180)"; sleep 1; done; echo "❌ Esplora did not start within 180s"; exit 1'
    ./scripts/e2e-test.sh {{args}}

# Run upstream arkd Go e2e tests against the dark Rust server.
# Requires Go, protoc, and the submodule populated:
#   git submodule update --init vendor/arkd
go-e2e: build
    @bash -c 'test -f vendor/arkd/go.mod || { echo "❌ vendor/arkd not initialized. Run: git submodule update --init vendor/arkd"; exit 1; }'
    @echo "→ Stopping Nigiri and clearing blockchain state..."
    nigiri stop || true
    @bash -c 'DATADIR="${HOME}/Library/Application Support/Nigiri"; rm -rf "${DATADIR}/volumes/bitcoin/regtest" "${DATADIR}/volumes/electrs" && echo "  ✅ Blockchain data cleared (fresh regtest)"'
    nigiri start
    @echo "⏳ Waiting for Esplora (chopsticks:3000) to be ready..."
    @bash -c 'for i in $(seq 1 180); do h=$(curl -sf http://localhost:3000/blocks/tip/height 2>/dev/null); echo "$h" | grep -qE "^[0-9]+$" && echo "✅ Esplora ready (block $h)" && exit 0; if [ $((i % 15)) -eq 0 ]; then exited=$(docker ps -a --filter name=chopsticks --filter status=exited -q 2>/dev/null); if [ -n "$exited" ]; then echo "  ⚠️  chopsticks crashed — restarting..."; docker restart chopsticks 2>/dev/null || true; fi; fi; echo "  waiting... ($i/180)"; sleep 1; done; echo "❌ Esplora did not start within 180s"; exit 1'
    ./scripts/go-e2e.sh

# Stop Nigiri (run this manually when you are done testing)
nigiri-stop:
    nigiri stop

# =============================================================================
# REST wallet daemon (dark-wallet-rest)
# =============================================================================

# Regenerate the committed OpenAPI spec for dark-wallet-rest.
# Run after changing REST routes or DTOs; CI fails if the committed spec drifts.
generate-rest-openapi:
    cargo run --quiet -p dark-wallet-rest --bin dump-openapi > crates/dark-wallet-rest/openapi.json
    @echo "✅ Wrote crates/dark-wallet-rest/openapi.json"

# Fail if the committed openapi.json differs from a freshly generated one.
check-rest-openapi:
    @cargo run --quiet -p dark-wallet-rest --bin dump-openapi > /tmp/dark-openapi.json
    @diff -q crates/dark-wallet-rest/openapi.json /tmp/dark-openapi.json \
        || { echo "❌ openapi.json drift — run: just generate-rest-openapi"; exit 1; }
    @echo "✅ openapi.json is up to date"

# Run the REST wallet daemon against a locally-running dark server.
rest *args:
    cargo run -p dark-wallet-rest --bin dark-wallet-rest -- {{args}}

# Regenerate both the committed OpenAPI spec AND the downstream clients
# (Rust `dark-rest-client` + TypeScript `web/lib/gen/dark.ts`).
# The Rust client is hand-maintained; this target only regenerates the spec
# and the TS types. Review `crates/dark-rest-client/src/lib.rs` by hand after
# adding new endpoints.
generate-rest-client: generate-rest-openapi
    @cd web && npm install --silent && npm run --silent generate \
        || { echo "⚠️  'openapi-typescript' not available — run 'cd web && npm install' first"; exit 1; }
    @echo "✅ Regenerated web/lib/gen/dark.ts"

# Generate just the TypeScript client (skip the OpenAPI refresh).
generate-rest-ts-client:
    cd web && npm install --silent && npm run --silent generate
