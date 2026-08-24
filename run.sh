#!/usr/bin/env bash
# Convenience wrapper around sip_test.py
# Usage: ./run.sh {diagnose|options|call|listen} [--verbose]
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD="${1:-diagnose}"
shift || true
exec python3 "$DIR/sip_test.py" "$CMD" --config "$DIR/config.env" "$@"
