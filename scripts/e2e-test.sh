#!/usr/bin/env bash
# End-to-end integration test using Nigiri (Bitcoin regtest + Esplora)
# Usage: ./scripts/e2e-test.sh
set -euo pipefail

GRPC="localhost:50051"
CONFIG="tests/nigiri-config.toml"

echo "=== arkd-rs E2E Test ==="

# 1. Check Nigiri is running
if ! curl -sf http://localhost:3000/blocks/tip/height > /dev/null 2>&1; then
  echo "ERROR: Nigiri not running. Start with: nigiri start"
  exit 1
fi
echo "✅ Nigiri running"

# 2. Build arkd
cargo build --release 2>&1 | tail -3
echo "✅ Binary built"

# 3. Start arkd
./target/release/arkd &
ARKD_PID=$!
trap "kill $ARKD_PID 2>/dev/null || true" EXIT
sleep 2

# 4. Check GetInfo
echo "--- GetInfo ---"
if command -v grpcurl > /dev/null 2>&1; then
  grpcurl -plaintext $GRPC ark.v1.ArkService/GetInfo
  echo "✅ GetInfo works"
else
  echo "grpcurl not installed — skipping gRPC check"
  # Fallback: check process is running
  kill -0 $ARKD_PID && echo "✅ arkd process running"
fi

echo ""
echo "=== All checks passed ==="
