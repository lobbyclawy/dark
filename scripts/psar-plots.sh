#!/usr/bin/env bash
# scripts/psar-plots.sh — Generate SVG figures for issue #687.
#
# Wrapper around the Python script `scripts/psar-plots.py`. The
# Python implementation is stdlib-only (no matplotlib / gnuplot
# dependency) so this works on a clean checkout without `pip install`
# / `brew install` ceremony.
#
# Outputs: docs/benchmarks/figures/{boarding-vs-n,epoch-vs-k,storage-vs-k}.svg

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$REPO_ROOT/scripts/psar-plots.py" "$@"
