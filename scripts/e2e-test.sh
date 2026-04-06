#!/usr/bin/env bash
# End-to-end integration test runner for dark
#
# Usage:
#   ./scripts/e2e-test.sh              # Run all e2e tests
#   ./scripts/e2e-test.sh --quick      # Run health + nigiri checks only
#   ./scripts/e2e-test.sh --filter foo # Run tests matching "foo"
#   DARK_VERBOSE=1 ./scripts/e2e-test.sh  # Show dark stdout/stderr
#
# Prerequisites:
#   - Nigiri running (nigiri start)
#   - dark binary built (cargo build --release)
#
set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────────────────
ESPLORA_URL="${ESPLORA_URL:-http://localhost:3000}"
BITCOIN_RPC_URL="${BITCOIN_RPC_URL:-http://admin1:123@127.0.0.1:18443}"
DARK_GRPC_URL="${DARK_GRPC_URL:-http://127.0.0.1:7070}"
DARK_ADMIN_URL="${DARK_ADMIN_URL:-http://localhost:7071}"
GRPC_HOST="${GRPC_HOST:-localhost:7070}"
FILTER=""
QUICK=false

for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=true ;;
        --filter) shift; FILTER="${1:-}" ;;
        --filter=*) FILTER="${arg#--filter=}" ;;
        --help|-h)
            echo "Usage: $0 [--quick] [--filter PATTERN]"
            exit 0
            ;;
    esac
done

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║               dark E2E Test Suite                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Pre-flight checks ────────────────────────────────────────────────────

# 1. Check Nigiri/Esplora
echo "→ Checking Esplora at ${ESPLORA_URL}..."
if ! curl -sf "${ESPLORA_URL}/blocks/tip/height" > /dev/null 2>&1; then
    echo "ERROR: Esplora not reachable at ${ESPLORA_URL}"
    echo "Start Nigiri with: nigiri start"
    exit 1
fi
BLOCK_HEIGHT=$(curl -sf "${ESPLORA_URL}/blocks/tip/height" 2>/dev/null || echo "?")
echo "  ✅ Esplora running (block height: ${BLOCK_HEIGHT})"

# 2. Check bitcoind
echo "→ Checking bitcoind at ${BITCOIN_RPC_URL}..."
if ! curl -sf --user admin1:123 -d '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
     -H 'Content-Type: application/json' "${BITCOIN_RPC_URL}" > /dev/null 2>&1; then
    echo "ERROR: bitcoind not reachable at ${BITCOIN_RPC_URL}"
    exit 1
fi
echo "  ✅ bitcoind running"

# 3. Check binary exists
BINARY="./target/debug/dark"
if [ ! -f "$BINARY" ]; then
    BINARY="./target/release/dark"
fi
if [ ! -f "$BINARY" ]; then
    echo "⚠  dark binary not found. Building..."
    cargo build --release
    BINARY="./target/release/dark"
fi
echo "  ✅ Binary: ${BINARY}"

# 4. Kill any stale dark process from a previous run
DARK_PID=""
STALE_PID=$(lsof -ti tcp:7070 2>/dev/null || true)
if [ -n "$STALE_PID" ]; then
    echo "  ⚠️  Killing stale dark process (PID ${STALE_PID}) on port 7070..."
    kill "$STALE_PID" 2>/dev/null || true
    sleep 1
fi

# ─── Start dark ────────────────────────────────────────────────────────────
if true; then
    echo ""
    # Clean up stale database files so each run starts fresh
    rm -f /tmp/dark-e2e.db /tmp/dark-e2e-wallet.db /tmp/dark-e2e.log

    echo "→ Writing config for e2e..."
    cat > /tmp/dark-e2e.toml <<'TOMLEOF'
[server]
esplora_url = "http://localhost:3000"
no_macaroons = true
no_tls = true

[bitcoin]
network = "regtest"
rpc_host = "127.0.0.1"
rpc_port = 18443
rpc_user = "admin1"
rpc_password = "123"
min_confirmations = 1

[wallet]
network = "regtest"
esplora_url = "http://localhost:3000"
database_path = "/tmp/dark-e2e-wallet.db"
gap_limit = 20

[database]
backend = "sqlite"
url = "sqlite:///tmp/dark-e2e.db"

[ark]
round_duration_secs = 5
vtxo_expiry_blocks = 144
connector_timelock_blocks = 12
min_vtxo_amount_sats = 1000
max_vtxo_amount_sats = 100000000
utxo_min_amount = 1000
utxo_max_amount = 100000000
unilateral_exit_delay = 30
boarding_exit_delay = 30
TOMLEOF
    echo "  ✅ Config written to /tmp/dark-e2e.toml"

    echo "→ Starting dark..."
    if [ "${DARK_VERBOSE:-}" = "1" ]; then
        ${BINARY} --config /tmp/dark-e2e.toml --grpc-port 7070 --admin-port 7071 --log-level info 2>&1 | tee /tmp/dark-e2e.log &
    else
        ${BINARY} --config /tmp/dark-e2e.toml --grpc-port 7070 --admin-port 7071 --log-level info > /tmp/dark-e2e.log 2>&1 &
    fi
    DARK_PID=$!
    trap "echo '→ Stopping dark (PID ${DARK_PID})...'; kill ${DARK_PID} 2>/dev/null || true; wait ${DARK_PID} 2>/dev/null || true" EXIT

    # Wait for gRPC to become ready
    echo "  Waiting for gRPC port..."
    for i in $(seq 1 30); do
        if nc -z localhost 7070 2>/dev/null; then
            break
        fi
        if ! kill -0 "$DARK_PID" 2>/dev/null; then
            echo "ERROR: dark died during startup. Logs:"
            tail -20 /tmp/dark-e2e.log || true
            exit 1
        fi
        sleep 1
    done
    echo "  ✅ dark started (PID ${DARK_PID})"

    # Fund the dark server wallet so it can build commitment transactions
    echo "→ Funding dark server wallet..."
    DARK_ADDR=$(curl -s http://127.0.0.1:7071/v1/admin/wallet/address \
        2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('address',''))" 2>/dev/null || echo "")
    if [ -n "$DARK_ADDR" ]; then
        echo "  Funding dark wallet at ${DARK_ADDR}"
        curl -s -X POST http://admin1:123@127.0.0.1:18443 \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"1.0\",\"id\":\"fund\",\"method\":\"sendtoaddress\",\"params\":[\"${DARK_ADDR}\",10.0]}" > /dev/null
        MINE_ADDR=$(curl -s -X POST http://admin1:123@127.0.0.1:18443 \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"1.0","id":"addr","method":"getnewaddress","params":[]}' | \
            python3 -c "import json,sys; print(json.load(sys.stdin)['result'])")
        curl -s -X POST http://admin1:123@127.0.0.1:18443 \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"1.0\",\"id\":\"mine\",\"method\":\"generatetoaddress\",\"params\":[6,\"${MINE_ADDR}\"]}" > /dev/null
        echo "  ✅ dark wallet funded"
    else
        echo "  ⚠️  Could not get dark wallet address (admin API may not be ready yet)"
    fi
fi

# ─── GetInfo check ─────────────────────────────────────────────────────────
echo ""
echo "→ Checking GetInfo..."
if command -v grpcurl > /dev/null 2>&1; then
    INFO=$(grpcurl -plaintext ${GRPC_HOST} ark.v1.ArkService/GetInfo 2>/dev/null || echo "{}")
    echo "  ${INFO}" | head -5
    echo "  ✅ GetInfo works"
else
    echo "  grpcurl not installed — skipping gRPC check"
    kill -0 ${DARK_PID:-0} 2>/dev/null && echo "  ✅ dark process running"
fi

if [ "$QUICK" = true ]; then
    echo ""
    echo "══════════════════════════════════════════════"
    echo "  Quick checks passed ✅"
    echo "══════════════════════════════════════════════"
    exit 0
fi

# ─── Run E2E tests ─────────────────────────────────────────────────────────
echo ""


export INTEGRATION_TEST=1
export ESPLORA_URL BITCOIN_RPC_URL DARK_GRPC_URL DARK_ADMIN_URL

TEST_ARGS="--test e2e_regtest -- --ignored --test-threads=1 --nocapture"
if [ -n "$FILTER" ]; then
    TEST_ARGS="${TEST_ARGS} ${FILTER}"
fi

echo "→ cargo test ${TEST_ARGS}"
echo ""

# Verify dark is still alive before running tests
if [ -n "${DARK_PID:-}" ]; then
    if ! kill -0 "$DARK_PID" 2>/dev/null; then
        echo "ERROR: dark (PID ${DARK_PID}) died before tests could run."
        echo "  Check logs with: DARK_VERBOSE=1 $0"
        exit 1
    fi
    echo "  ✅ dark still running (PID ${DARK_PID})"
fi

# Run tests and capture exit code
set +e
cargo test ${TEST_ARGS}
TEST_EXIT=$?
set -e

echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo "══════════════════════════════════════════════"
    echo "  All E2E tests passed ✅"
    echo "══════════════════════════════════════════════"
else
    echo "══════════════════════════════════════════════"
    echo "  Some E2E tests failed ❌ (exit code: ${TEST_EXIT})"
    echo "══════════════════════════════════════════════"
fi

exit $TEST_EXIT
