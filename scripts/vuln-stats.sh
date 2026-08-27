#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PYTHON="$ROOT/backend/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
  echo "[VulnHunter] missing backend/.venv — run sh start.sh first" >&2
  exit 1
fi
exec "$PYTHON" "$SCRIPT_DIR/vuln_stats.py" "$@"
