#!/usr/bin/env bash
# Go e2e test runner — runs arkade-os/arkd Go tests against the dark Rust server.
#
# Usage:
#   ./scripts/go-e2e.sh
#   DARK_VERBOSE=1 ./scripts/go-e2e.sh   # Show dark stdout/stderr
#
# Prerequisites:
#   - Nigiri running (handled by `just go-e2e`)
#   - dark binary built (handled by `just go-e2e`)
#   - Go installed
#   - vendor/arkd submodule populated: git submodule update --init vendor/arkd
#
set -euo pipefail

# ─── Configuration ─────────────────────────────────────────────────────────
BINARY="./target/debug/dark"
if [ ! -f "$BINARY" ]; then
    BINARY="./target/release/dark"
fi
if [ ! -f "$BINARY" ]; then
    echo "❌ dark binary not found. Run: cargo build"
    exit 1
fi
echo "  ✅ Binary: ${BINARY}"

# ─── Kill stale dark process ────────────────────────────────────────────────
STALE_PID=$(lsof -ti tcp:7070 2>/dev/null || true)
if [ -n "$STALE_PID" ]; then
    echo "  ⚠️  Killing stale dark process (PID ${STALE_PID}) on port 7070..."
    kill "$STALE_PID" 2>/dev/null || true
    sleep 1
fi

# ─── Write config ───────────────────────────────────────────────────────────
rm -f /tmp/dark-go-e2e.db /tmp/dark-go-e2e-wallet.db /tmp/dark-go-e2e.log

echo "→ Writing config..."
cat > /tmp/dark-go-e2e.toml <<'TOMLEOF'
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
database_path = "/tmp/dark-go-e2e-wallet.db"
gap_limit = 20

[database]
backend = "sqlite"
url = "sqlite:///tmp/dark-go-e2e.db"

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
echo "  ✅ Config written to /tmp/dark-go-e2e.toml"

# ─── Start dark ─────────────────────────────────────────────────────────────
echo "→ Starting dark..."
DARK_PID=""
MINER_PID=""

if [ "${DARK_VERBOSE:-}" = "1" ]; then
    ${BINARY} --config /tmp/dark-go-e2e.toml --grpc-port 7070 --admin-port 7071 --log-level debug 2>&1 | tee /tmp/dark-go-e2e.log &
else
    ${BINARY} --config /tmp/dark-go-e2e.toml --grpc-port 7070 --admin-port 7071 --log-level debug > /tmp/dark-go-e2e.log 2>&1 &
fi
DARK_PID=$!

trap '
    echo ""
    echo "→ Cleaning up..."
    [ -n "${MINER_PID:-}" ] && kill "$MINER_PID" 2>/dev/null || true
    [ -n "${DARK_PID:-}" ] && { echo "→ Stopping dark (PID ${DARK_PID})..."; kill "$DARK_PID" 2>/dev/null || true; wait "$DARK_PID" 2>/dev/null || true; }
' EXIT

# Wait for gRPC port 7070
echo "  Waiting for dark gRPC port..."
for i in $(seq 1 60); do
    if nc -z 127.0.0.1 7070 2>/dev/null; then
        echo "  ✅ dark gRPC ready on :7070"
        break
    fi
    if ! kill -0 "$DARK_PID" 2>/dev/null; then
        echo "❌ dark died during startup. Logs:"
        tail -20 /tmp/dark-go-e2e.log || true
        exit 1
    fi
    echo "    waiting... ($i/60)"
    sleep 1
done

if ! nc -z 127.0.0.1 7070 2>/dev/null; then
    echo "❌ dark failed to start within 60s. Logs:"
    tail -30 /tmp/dark-go-e2e.log || true
    exit 1
fi

# Wait for admin HTTP port 7071
echo "  Waiting for dark admin HTTP port..."
for i in $(seq 1 10); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:7071/v1/admin/wallet/status 2>/dev/null || echo "000")
    if [ "$STATUS" != "000" ]; then
        echo "  ✅ dark admin HTTP ready on :7071"
        break
    fi
    echo "    waiting... ($i/10)"
    sleep 1
done

# ─── Seed and fund wallet ───────────────────────────────────────────────────
echo ""
echo "→ Seeding and funding dark server wallet..."
BASE="http://127.0.0.1:7071"

WALLET_STATUS=$(curl -s "$BASE/v1/admin/wallet/status")
echo "  Wallet status: $WALLET_STATUS"
INITIALIZED=$(echo "$WALLET_STATUS" | python3 -c "import json,sys; print(json.load(sys.stdin).get('initialized', False))" 2>/dev/null || echo "false")

if [ "$INITIALIZED" != "True" ]; then
    SEED=$(curl -s "$BASE/v1/admin/wallet/seed" | python3 -c "import json,sys; print(json.load(sys.stdin)['seed'])")
    echo "  Got seed (first word): $(echo "$SEED" | cut -d' ' -f1)..."
    curl -s -X POST "$BASE/v1/admin/wallet/create" \
        -H "Content-Type: application/json" \
        -d "{\"seed\": \"$SEED\", \"password\": \"password\"}" > /dev/null
    echo "  Wallet created"
fi

curl -s -X POST "$BASE/v1/admin/wallet/unlock" \
    -H "Content-Type: application/json" \
    -d '{"password": "password"}' > /dev/null
echo "  Wallet unlocked"

sleep 2

ADDRESS=$(curl -s "$BASE/v1/admin/wallet/address" | python3 -c "import json,sys; print(json.load(sys.stdin)['address'])")
echo "  Dark wallet address: $ADDRESS"

for i in $(seq 1 15); do
    curl -s -X POST http://admin1:123@127.0.0.1:18443 \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"1.0\",\"id\":\"fund${i}\",\"method\":\"sendtoaddress\",\"params\":[\"${ADDRESS}\",1.0]}" > /dev/null 2>&1 || true
done
echo "  Funded wallet with 15 BTC"

MINE_ADDR=$(curl -s -X POST http://admin1:123@127.0.0.1:18443 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"1.0","id":"addr","method":"getnewaddress","params":[]}' | \
    python3 -c "import json,sys; print(json.load(sys.stdin)['result'])")
curl -s -X POST http://admin1:123@127.0.0.1:18443 \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"1.0\",\"id\":\"mine\",\"method\":\"generatetoaddress\",\"params\":[6,\"${MINE_ADDR}\"]}" > /dev/null
echo "  Mined 6 blocks"

# Wait for wallet to reflect balance
for i in $(seq 1 15); do
    BALANCE=$(curl -s "$BASE/v1/admin/wallet/balance" | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('mainAccount',{}).get('available','0'))" 2>/dev/null || echo "0")
    echo "  [$i] Dark wallet balance: $BALANCE BTC"
    NONZERO=$(python3 -c "print('yes' if float('${BALANCE}') > 0 else 'no')" 2>/dev/null || echo "no")
    if [ "$NONZERO" = "yes" ]; then
        echo "  ✅ Dark wallet funded: $BALANCE BTC"
        break
    fi
    sleep 2
done

# ─── Background block miner ─────────────────────────────────────────────────
echo ""
echo "→ Starting background block miner (1 block every 2s)..."
(
    while true; do
        MINE_ADDR=$(curl -s -X POST http://admin1:123@127.0.0.1:18443 \
            -H "Content-Type: application/json" \
            -d '{"jsonrpc":"1.0","id":"addr","method":"getnewaddress","params":[]}' | \
            python3 -c "import json,sys; print(json.load(sys.stdin)['result'])" 2>/dev/null || echo "")
        if [ -n "$MINE_ADDR" ]; then
            curl -s -X POST http://admin1:123@127.0.0.1:18443 \
                -H "Content-Type: application/json" \
                -d "{\"jsonrpc\":\"1.0\",\"id\":\"mine\",\"method\":\"generatetoaddress\",\"params\":[1,\"${MINE_ADDR}\"]}" > /dev/null 2>&1 || true
        fi
        sleep 2
    done
) &
MINER_PID=$!
echo "  ✅ Background block miner started (PID ${MINER_PID})"

# ─── Apply debug patch ──────────────────────────────────────────────────────
echo ""
echo "→ Applying Go e2e debug logging patch..."
(
    cd vendor/arkd
    # Only apply if not already applied
    if git apply --check ../../.github/go-e2e-debug.patch 2>/dev/null; then
        git apply ../../.github/go-e2e-debug.patch
        echo "  ✅ Debug logging patch applied"
    else
        echo "  ℹ️  Patch already applied or not applicable — skipping"
    fi
)

# ─── Run Go e2e tests ───────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Running arkade-os/arkd Go E2E Tests              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

set +e
(cd vendor/arkd && go test -v -count 1 -timeout 3600s github.com/arkade-os/arkd/internal/test/e2e)
TEST_EXIT=$?
set -e

echo ""
if [ $TEST_EXIT -eq 0 ]; then
    echo "══════════════════════════════════════════════"
    echo "  All Go E2E tests passed ✅"
    echo "══════════════════════════════════════════════"
else
    echo "══════════════════════════════════════════════"
    echo "  Some Go E2E tests failed ❌ (exit code: ${TEST_EXIT})"
    echo "  Dark logs: /tmp/dark-go-e2e.log"
    echo "══════════════════════════════════════════════"
fi

exit $TEST_EXIT
