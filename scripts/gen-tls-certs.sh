#!/usr/bin/env bash
# Generate self-signed TLS certificate for development
# Usage: ./scripts/gen-tls-certs.sh [output_dir]
set -euo pipefail

OUTPUT="${1:-./certs}"
mkdir -p "$OUTPUT"

# WARNING: -nodes skips passphrase encryption for convenience.
# This is intentional for local development only.
# In production, use a proper CA, cert-manager, or Let's Encrypt — never -nodes.
openssl req -x509 -newkey rsa:4096 -keyout "$OUTPUT/key.pem" \
  -out "$OUTPUT/cert.pem" -days 365 -nodes \
  -subj "/CN=dark-dev/O=dark/C=US"

echo "Generated: $OUTPUT/cert.pem and $OUTPUT/key.pem"
echo "WARNING: These are unencrypted dev-only certificates. Do not use in production."
