#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT/backend"
if [ ! -x .venv/bin/python ]; then
  echo "[VulnHunter] missing backend/.venv — run sh start.sh first" >&2
  exit 1
fi
exec .venv/bin/python -m pytest -q "$@"
