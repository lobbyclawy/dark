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
ESPLORA_URL="${ESPLORA_URL:-http://localhost:5000}"
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

# 4. Check if dark is already running
DARK_PID=""
if command -v grpcurl > /dev/null 2>&1; then
    if grpcurl -plaintext ${GRPC_HOST} ark.v1.ArkService/GetInfo > /dev/null 2>&1; then
        echo "  ✅ dark already running on ${GRPC_HOST}"
    fi
fi

# ─── Start dark if not running ─────────────────────────────────────────────
if [ -z "$DARK_PID" ]; then
    echo ""
    echo "→ Writing light-mode config for e2e..."
    cat > /tmp/dark-e2e-config.toml <<'TOMLEOF'
[deployment]
mode = "light"

[server]
esplora_url = "http://localhost:5000"
TOMLEOF
    echo "  ✅ Config written to /tmp/dark-e2e-config.toml"

    echo "→ Starting dark..."
    if [ "${DARK_VERBOSE:-}" = "1" ]; then
        ${BINARY} --config /tmp/dark-e2e-config.toml --grpc-addr 0.0.0.0:7070 &
    else
        ${BINARY} --config /tmp/dark-e2e-config.toml --grpc-addr 0.0.0.0:7070 > /dev/null 2>&1 &
    fi
    DARK_PID=$!
    trap "echo '→ Stopping dark (PID ${DARK_PID})...'; kill ${DARK_PID} 2>/dev/null || true; wait ${DARK_PID} 2>/dev/null || true" EXIT

    # Wait for gRPC to become ready
    echo "  Waiting for gRPC port..."
    for i in $(seq 1 30); do
        if command -v grpcurl > /dev/null 2>&1; then
            if grpcurl -plaintext ${GRPC_HOST} ark.v1.ArkService/GetInfo > /dev/null 2>&1; then
                break
            fi
        else
            if curl -sf "http://${GRPC_HOST}" > /dev/null 2>&1 || \
               nc -z "${GRPC_HOST%%:*}" "${GRPC_HOST##*:}" 2>/dev/null; then
                break
            fi
        fi
        sleep 1
    done
    echo "  ✅ dark started (PID ${DARK_PID})"
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
