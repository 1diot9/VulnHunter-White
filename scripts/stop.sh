#!/bin/sh
# Kill VulnHunter backend/frontend. Usage: stop.sh [--quiet]
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PIDDIR="$ROOT/data/run"
QUIET=0
if [ "${1:-}" = "--quiet" ]; then
  QUIET=1
fi

if [ "$QUIET" -eq 0 ]; then
  echo "[VulnHunter] stopping..."
fi

kill_tree() {
  pid=$1
  case "$pid" in
    ''|*[!0-9]*) return 0 ;;
  esac
  if [ "$pid" -le 1 ]; then
    return 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -P "$pid" 2>/dev/null | while IFS= read -r child; do
      kill_tree "$child"
    done
  fi
  if [ "$QUIET" -eq 0 ]; then
    echo "  kill pid $pid${2:+ on port $2}"
  fi
  kill -TERM "$pid" 2>/dev/null || true
}

pids_on_port() {
  port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null || true
    return 0
  fi
  if command -v fuser >/dev/null 2>&1; then
    # fuser prints pids to stdout; stderr has the port label
    fuser "${port}/tcp" 2>/dev/null | tr -cs '0-9' '\n' | grep -E '^[0-9]+$' || true
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    ss -lptn "sport = :${port}" 2>/dev/null | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' || true
    return 0
  fi
}

stop_pidfile() {
  f=$1
  if [ ! -f "$f" ]; then
    return 0
  fi
  pid=$(tr -d ' \t\r\n' < "$f" 2>/dev/null || true)
  if [ -n "$pid" ]; then
    kill_tree "$pid"
    n=0
    while [ "$n" -lt 8 ] && kill -0 "$pid" 2>/dev/null; do
      n=$((n + 1))
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      if command -v pgrep >/dev/null 2>&1; then
        pgrep -P "$pid" 2>/dev/null | while IFS= read -r child; do
          kill -KILL "$child" 2>/dev/null || true
        done
      fi
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$f"
}

stop_pidfile "$PIDDIR/backend.pid"
stop_pidfile "$PIDDIR/frontend.pid"

# Same as Windows stop.cmd: free 8000 / 5173 even if pid files are stale.
for port in 8000 5173; do
  pids_on_port "$port" | while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    kill_tree "$pid" "$port"
    sleep 1
    kill -KILL "$pid" 2>/dev/null || true
  done
done

# Leftover uvicorn / vite still rooted in this checkout
if command -v pgrep >/dev/null 2>&1; then
  pgrep -f "$ROOT/backend/.venv/bin/uvicorn" 2>/dev/null | while IFS= read -r pid; do
    kill_tree "$pid"
    kill -KILL "$pid" 2>/dev/null || true
  done
  pgrep -f "$ROOT/frontend" 2>/dev/null | while IFS= read -r pid; do
    comm=$(ps -p "$pid" -o comm= 2>/dev/null | tr -d ' \t' || true)
    case "$comm" in
      node*|nodejs*|npm*|vite*)
        kill_tree "$pid"
        kill -KILL "$pid" 2>/dev/null || true
        ;;
    esac
  done
fi

rm -f "$PIDDIR/backend.pid" "$PIDDIR/frontend.pid"

if [ "$QUIET" -eq 0 ]; then
  echo "[VulnHunter] stopped."
fi
