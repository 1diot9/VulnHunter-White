#!/bin/sh
# Foreground frontend; prefer ../start.sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
LOGDIR="$ROOT/data/logs"
mkdir -p "$LOGDIR"

cd "$ROOT/frontend"
if ! command -v npm >/dev/null 2>&1; then
  echo "[VulnHunter] npm not found" >>"$LOGDIR/frontend.log"
  exit 1
fi
exec npm run dev -- --host 127.0.0.1 >>"$LOGDIR/frontend.log" 2>&1
