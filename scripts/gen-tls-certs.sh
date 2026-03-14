#!/usr/bin/env bash
# Generate self-signed TLS certificate for development
# Usage: ./scripts/gen-tls-certs.sh [output_dir]
set -euo pipefail

OUTPUT="${1:-./certs}"
mkdir -p "$OUTPUT"

openssl req -x509 -newkey rsa:4096 -keyout "$OUTPUT/key.pem" \
  -out "$OUTPUT/cert.pem" -days 365 -nodes \
  -subj "/CN=arkd-dev/O=arkd/C=US"

echo "Generated: $OUTPUT/cert.pem and $OUTPUT/key.pem"
