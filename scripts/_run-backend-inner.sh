#!/bin/sh
# Foreground backend; prefer ../start.sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOGDIR="$ROOT/data/logs"
mkdir -p "$LOGDIR"
VULNHUNTER_PORT="${VULNHUNTER_PORT:-16780}"
VULNHUNTER_HOST="${VULNHUNTER_HOST:-127.0.0.1}"

if [ "${1:-}" = "--reload" ]; then
  VULNHUNTER_RELOAD=1
fi

ROTATOR="$ROOT/scripts/rotate_log.py"
PY="$ROOT/backend/.venv/bin/python"
if [ ! -x "$PY" ]; then
  PY=$(command -v python3 || command -v python || true)
fi
if [ -z "$PY" ]; then
  echo "[VulnHunter] python not found; cannot write data/logs" >&2
  exit 1
fi

write_log() {
  printf '%s\n' "$1" | "$PY" "$ROTATOR" --dir "$LOGDIR" --prefix backend
}

cd "$ROOT/backend"
if [ ! -x "$ROOT/backend/.venv/bin/uvicorn" ]; then
  write_log "[VulnHunter] missing backend/.venv — run sh start.sh first"
  exit 1
fi

# timeout-graceful-shutdown: SSE otherwise reload waits forever for connections to close
if [ -n "${VULNHUNTER_RELOAD:-}" ]; then
  exec "$PY" "$ROTATOR" --dir "$LOGDIR" --prefix backend -- \
    "$ROOT/backend/.venv/bin/uvicorn" app.main:app \
    --reload --reload-dir app \
    --timeout-graceful-shutdown 2 --host "$VULNHUNTER_HOST" --port "$VULNHUNTER_PORT"
fi
exec "$PY" "$ROTATOR" --dir "$LOGDIR" --prefix backend -- \
  "$ROOT/backend/.venv/bin/uvicorn" app.main:app \
  --timeout-graceful-shutdown 2 --host "$VULNHUNTER_HOST" --port "$VULNHUNTER_PORT"
