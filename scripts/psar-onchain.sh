#!/usr/bin/env bash
# scripts/psar-onchain.sh — On-chain footprint measurement for issue #685.
#
# Drives the existing #669 regtest publication (`publish_slot_attest`)
# against a running Nigiri node and reports the on-chain `slot_attest`
# transaction's input/witness/output bytes, weight, and vbytes. The
# per-batch (Ark commitment tx) overhead is documented analytically
# in `docs/benchmarks/psar-onchain.md` because PSAR does not introduce
# new commitment-tx structure beyond standard Ark.
#
# Requirements:
#   - Nigiri running locally (`nigiri start`).
#   - `bitcoin-cli` reachable on Nigiri's regtest port.
#
# Usage:
#   scripts/psar-onchain.sh [--out PATH]
#
# Output: markdown table on stdout (or to --out PATH).
#
# When Nigiri is not running, the script prints the documented run
# command and exits 0; the analytical formulas in the markdown
# remain authoritative until a real measurement lands.

set -euo pipefail

OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

NIGIRI_RPC_URL="${BITCOIN_RPC_URL:-http://admin1:123@127.0.0.1:18443}"

# Sanity check: is Nigiri reachable?
if ! curl -s --max-time 2 -o /dev/null \
     -X POST -H 'content-type: text/plain' \
     --data '{"jsonrpc":"1.0","id":"psar-onchain","method":"getblockchaininfo","params":[]}' \
     "$NIGIRI_RPC_URL" 2>/dev/null
then
  cat <<'EOM' >&2
psar-onchain.sh: Nigiri RPC not reachable at $BITCOIN_RPC_URL.

To run end-to-end:
  1. nigiri start
  2. cargo test -p dark-psar --features regtest --test e2e_psar_regtest \
       -- --ignored --test-threads=1
  3. scripts/psar-onchain.sh

Until Nigiri is up, see docs/benchmarks/psar-onchain.md for the
analytical footprint formulas — they are tight upper bounds against
which the measured numbers will compare.
EOM
  exit 0
fi

# Run the regtest e2e test under criterion-style capture.
# The test emits the txid + raw hex to stdout; we parse and ask
# bitcoind for the canonical decoded weight/vbyte numbers.
TEST_LOG=$(mktemp)
trap 'rm -f "$TEST_LOG"' EXIT
BITCOIN_RPC_URL="$NIGIRI_RPC_URL" \
cargo test -p dark-psar --features regtest --test e2e_psar_regtest \
  -- --ignored --test-threads=1 --nocapture 2>&1 | tee "$TEST_LOG" >&2

# Parse the emitted txid (test prints `slot_attest_txid: <hex>`).
TXID=$(grep -oE 'slot_attest_txid: [0-9a-f]{64}' "$TEST_LOG" | head -1 | awk '{print $2}')
if [ -z "$TXID" ]; then
  echo "psar-onchain.sh: failed to parse slot_attest txid from test output" >&2
  exit 3
fi

# Authoritative tx info from bitcoind.
RAW=$(curl -s -X POST -H 'content-type: text/plain' \
  --data "{\"jsonrpc\":\"1.0\",\"id\":\"psar-onchain\",\"method\":\"getrawtransaction\",\"params\":[\"$TXID\", true]}" \
  "$NIGIRI_RPC_URL")

INPUT_BYTES=$(echo "$RAW" | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(sum(len(v.get('scriptSig', {}).get('hex','')) // 2 for v in r['vin']))")
WITNESS_BYTES=$(echo "$RAW" | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(sum(sum(len(w) // 2 for w in v.get('txinwitness', [])) for v in r['vin']))")
OUTPUT_BYTES=$(echo "$RAW" | python3 -c "import json,sys; r=json.load(sys.stdin)['result']; print(sum(len(v['scriptPubKey']['hex']) // 2 for v in r['vout']))")
WEIGHT=$(echo "$RAW" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['weight'])")
VSIZE=$(echo "$RAW" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['vsize'])")
SIZE=$(echo "$RAW" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['size'])")

emit() {
  echo "## Measured on-chain footprint (Nigiri regtest)"
  echo
  echo "| Tx kind        | size (B) | input (B) | witness (B) | output (B) | weight (WU) | vbytes |"
  echo "|----------------|----------|-----------|-------------|------------|-------------|--------|"
  printf "| slot_attest_S  | %8d | %9d | %11d | %10d | %11d | %6d |\n" \
    "$SIZE" "$INPUT_BYTES" "$WITNESS_BYTES" "$OUTPUT_BYTES" "$WEIGHT" "$VSIZE"
}

if [ -n "$OUT" ]; then
  emit > "$OUT"
  echo "wrote $OUT" >&2
else
  emit
fi
