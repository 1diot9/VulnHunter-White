#!/bin/sh
# Foreground backend; prefer ../start.sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOGDIR="$ROOT/data/logs"
mkdir -p "$LOGDIR"
VULNHUNTER_PORT="${VULNHUNTER_PORT:-16780}"

if [ "${1:-}" = "--reload" ]; then
  VULNHUNTER_RELOAD=1
fi

cd "$ROOT/backend"
if [ ! -x "$ROOT/backend/.venv/bin/uvicorn" ]; then
  echo "[VulnHunter] missing backend/.venv — run sh start.sh first" >>"$LOGDIR/backend.log"
  exit 1
fi

# timeout-graceful-shutdown: SSE otherwise reload waits forever for connections to close
if [ -n "${VULNHUNTER_RELOAD:-}" ]; then
  exec "$ROOT/backend/.venv/bin/uvicorn" app.main:app \
    --reload --reload-dir app \
    --timeout-graceful-shutdown 2 --host 127.0.0.1 --port "$VULNHUNTER_PORT" \
    >>"$LOGDIR/backend.log" 2>&1
else
  exec "$ROOT/backend/.venv/bin/uvicorn" app.main:app \
    --timeout-graceful-shutdown 2 --host 127.0.0.1 --port "$VULNHUNTER_PORT" \
    >>"$LOGDIR/backend.log" 2>&1
fi
