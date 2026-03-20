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

# Run E2E regtest suite (starts Nigiri, waits for readiness, runs tests, stops Nigiri)
e2e *args: build
    nigiri start
    @echo "⏳ Waiting for Esplora to be ready..."
    @until curl -sf http://localhost:5000/blocks/tip/height > /dev/null 2>&1; do sleep 1; done
    @echo "✅ Esplora ready"
    ./scripts/e2e-test.sh {{args}}
    nigiri stop
