#!/bin/sh
set -eu
BACKEND_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$BACKEND_DIR/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "[VulnHunter] missing backend/.venv — run sh start.sh first" >&2
  exit 1
fi
exec "$PYTHON" "$BACKEND_DIR/../scripts/vuln_stats.py" "$@"
