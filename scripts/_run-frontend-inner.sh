#!/bin/sh
# Foreground frontend; prefer ../start.sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOGDIR="$ROOT/data/logs"
mkdir -p "$LOGDIR"
VULNHUNTER_FRONTEND_PORT="${VULNHUNTER_FRONTEND_PORT:-15173}"
VULNHUNTER_HOST="${VULNHUNTER_HOST:-127.0.0.1}"
export VULNHUNTER_PORT="${VULNHUNTER_PORT:-16780}"
export VULNHUNTER_FRONTEND_PORT
export VULNHUNTER_HOST

ROTATOR="$ROOT/scripts/rotate_log.py"
PY="$ROOT/backend/.venv/bin/python"
if [ ! -x "$PY" ]; then
  PY=$(command -v python3 || command -v python || true)
fi
if [ -z "$PY" ]; then
  echo "[VulnHunter] python not found; cannot write data/logs" >&2
  exit 1
fi

cd "$ROOT/frontend"
if ! command -v npm >/dev/null 2>&1; then
  printf '%s\n' "[VulnHunter] npm not found" | "$PY" "$ROTATOR" --dir "$LOGDIR" --prefix frontend
  exit 1
fi
exec "$PY" "$ROTATOR" --dir "$LOGDIR" --prefix frontend -- \
  npm run dev -- --host "$VULNHUNTER_HOST" --port "$VULNHUNTER_FRONTEND_PORT" --strictPort
