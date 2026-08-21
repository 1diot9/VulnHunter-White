#!/bin/sh
# Start backend (8000) + frontend (5173). First run creates venv / npm install.
# Usage: sh start.sh [--reload]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PIDDIR="$ROOT/data/run"
LOGDIR="$ROOT/data/logs"
mkdir -p "$PIDDIR" "$LOGDIR"

VULNHUNTER_RELOAD=
while [ $# -gt 0 ]; do
  case "$1" in
    --reload)
      VULNHUNTER_RELOAD=1
      ;;
    -h|--help)
      echo "Usage: start.sh [--reload]"
      exit 0
      ;;
    *)
      echo "[VulnHunter] unknown option: $1"
      echo "Usage: start.sh [--reload]"
      exit 1
      ;;
  esac
  shift
done
export VULNHUNTER_RELOAD

resolve_python() {
  cand=
  for cand in python3 python python3.12 python3.11; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        echo "$cand"
        return 0
      fi
    fi
  done
  return 1
}

port_listening() {
  port=$1
  if command -v lsof >/dev/null 2>&1; then
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
      return 0
    fi
    return 1
  fi
  if command -v netstat >/dev/null 2>&1; then
    if netstat -an 2>/dev/null | grep -Ei "[\.:]${port}[[:space:]].*listen" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  return 1
}

echo "[VulnHunter] starting..."

install_backend_deps() {
  PIP_INDEX_URL="${VULNHUNTER_PIP_INDEX_URL:-https://pypi.tuna.tsinghua.edu.cn/simple}"
  if ! "$ROOT/backend/.venv/bin/pip" install -r "$ROOT/backend/requirements.txt" -i "$PIP_INDEX_URL"; then
    echo "[VulnHunter] pip install failed with $PIP_INDEX_URL, retrying with the default index..."
    "$ROOT/backend/.venv/bin/pip" install -r "$ROOT/backend/requirements.txt"
  fi
}

if [ ! -x "$ROOT/backend/.venv/bin/python" ]; then
  echo "[VulnHunter] creating backend venv..."
  PY=
  if PY=$(resolve_python); then
    :
  else
    echo "[VulnHunter] need Python 3.11+ (python3 or python on PATH)."
    echo "  Debian/Ubuntu: sudo apt install python3 python3-venv python3-pip"
    echo "  macOS Homebrew: brew install python@3.12"
    exit 1
  fi
  "$PY" -m venv "$ROOT/backend/.venv"
fi

if [ ! -x "$ROOT/backend/.venv/bin/uvicorn" ]; then
  echo "[VulnHunter] installing backend deps..."
  install_backend_deps
fi

if [ ! -d "$ROOT/frontend/node_modules" ]; then
  echo "[VulnHunter] installing frontend deps..."
  if ! command -v npm >/dev/null 2>&1; then
    echo "[VulnHunter] npm not found. Install Node.js 20 LTS."
    exit 1
  fi
  ( cd "$ROOT/frontend" && npm install --registry=https://registry.npmmirror.com )
fi

sh "$ROOT/scripts/stop.sh" --quiet

if [ -n "$VULNHUNTER_RELOAD" ]; then
  echo "[VulnHunter] backend  http://127.0.0.1:8000  (reload)"
else
  echo "[VulnHunter] backend  http://127.0.0.1:8000"
fi

nohup sh "$ROOT/scripts/_run-backend-inner.sh" >/dev/null 2>&1 &
echo $! > "$PIDDIR/backend.pid"

echo "[VulnHunter] frontend http://127.0.0.1:5173"
nohup sh "$ROOT/scripts/_run-frontend-inner.sh" >/dev/null 2>&1 &
echo $! > "$PIDDIR/frontend.pid"

echo "[VulnHunter] waiting for ports..."
n=0
ready=
while [ "$n" -lt 45 ]; do
  if port_listening 8000 && port_listening 5173; then
    ready=1
    break
  fi
  n=$((n + 1))
  sleep 1
done

if [ -n "$ready" ]; then
  echo "[VulnHunter] ready."
else
  echo "[VulnHunter] warn: ports not ready yet — check data/logs/backend.log / frontend.log"
fi

echo
echo "  UI:   http://127.0.0.1:5173"
echo "  API:  http://127.0.0.1:8000/docs"
echo "  Stop: sh stop.sh"
echo "  Dev:  sh start.sh --reload"
echo "  Logs: data/logs/"
echo
