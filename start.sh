#!/bin/sh
# Start backend + frontend. First run creates venv / npm install.
# Usage: sh start.sh [--reload] [--lan] [--host ADDR] [--backend-port N] [--frontend-port N]
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PIDDIR="$ROOT/data/run"
LOGDIR="$ROOT/data/logs"
mkdir -p "$PIDDIR" "$LOGDIR"

# Defaults: 16780 / 15173 avoid the crowded 8000 and Vite 5173.
VULNHUNTER_PORT="${VULNHUNTER_PORT:-16780}"
VULNHUNTER_FRONTEND_PORT="${VULNHUNTER_FRONTEND_PORT:-15173}"
VULNHUNTER_HOST="${VULNHUNTER_HOST:-127.0.0.1}"
VULNHUNTER_RELOAD=

usage() {
  echo "Usage: start.sh [--reload] [--lan] [--host ADDR] [--backend-port N] [--frontend-port N]"
  echo "  --reload           uvicorn --reload"
  echo "  --lan              bind 0.0.0.0 (reachable on LAN)"
  echo "  --host ADDR        listen address (default 127.0.0.1, or VULNHUNTER_HOST)"
  echo "  --backend-port N   API port (default 16780, or VULNHUNTER_PORT)"
  echo "  --frontend-port N  UI port  (default 15173, or VULNHUNTER_FRONTEND_PORT)"
  echo "  aliases: --api-port / --ui-port"
}

valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
    return 1
  fi
  return 0
}

valid_host() {
  case "$1" in
    ''|-*) return 1 ;;
  esac
  case "$1" in
    *[[:space:]]*) return 1 ;;
  esac
  return 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --reload)
      VULNHUNTER_RELOAD=1
      ;;
    --lan)
      VULNHUNTER_HOST=0.0.0.0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --host)
      if [ $# -lt 2 ]; then
        echo "[VulnHunter] $1 needs a listen address (e.g. 0.0.0.0)"
        exit 1
      fi
      VULNHUNTER_HOST=$2
      shift
      ;;
    --host=*)
      VULNHUNTER_HOST=${1#*=}
      ;;
    --backend-port|--api-port)
      if [ $# -lt 2 ]; then
        echo "[VulnHunter] $1 needs a port number"
        exit 1
      fi
      VULNHUNTER_PORT=$2
      shift
      ;;
    --backend-port=*|--api-port=*)
      VULNHUNTER_PORT=${1#*=}
      ;;
    --frontend-port|--ui-port)
      if [ $# -lt 2 ]; then
        echo "[VulnHunter] $1 needs a port number"
        exit 1
      fi
      VULNHUNTER_FRONTEND_PORT=$2
      shift
      ;;
    --frontend-port=*|--ui-port=*)
      VULNHUNTER_FRONTEND_PORT=${1#*=}
      ;;
    *)
      echo "[VulnHunter] unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

if ! valid_port "$VULNHUNTER_PORT"; then
  echo "[VulnHunter] invalid VULNHUNTER_PORT: $VULNHUNTER_PORT"
  exit 1
fi
if ! valid_port "$VULNHUNTER_FRONTEND_PORT"; then
  echo "[VulnHunter] invalid VULNHUNTER_FRONTEND_PORT: $VULNHUNTER_FRONTEND_PORT"
  exit 1
fi
if [ "$VULNHUNTER_PORT" = "$VULNHUNTER_FRONTEND_PORT" ]; then
  echo "[VulnHunter] backend and frontend ports must differ"
  exit 1
fi
if ! valid_host "$VULNHUNTER_HOST"; then
  echo "[VulnHunter] invalid VULNHUNTER_HOST: $VULNHUNTER_HOST"
  exit 1
fi

export VULNHUNTER_PORT VULNHUNTER_FRONTEND_PORT VULNHUNTER_HOST VULNHUNTER_RELOAD

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

n=0
while [ "$n" -lt 10 ]; do
  if ! port_listening "$VULNHUNTER_PORT" && ! port_listening "$VULNHUNTER_FRONTEND_PORT"; then
    break
  fi
  n=$((n + 1))
  sleep 1
done
busy=
if port_listening "$VULNHUNTER_PORT"; then
  echo "[VulnHunter] error: backend port $VULNHUNTER_PORT is still in use"
  busy=1
fi
if port_listening "$VULNHUNTER_FRONTEND_PORT"; then
  echo "[VulnHunter] error: frontend port $VULNHUNTER_FRONTEND_PORT is still in use"
  busy=1
fi
if [ -n "$busy" ]; then
  echo "  Pick free ports: sh start.sh --backend-port N --frontend-port N"
  exit 1
fi

printf 'VULNHUNTER_PORT=%s\nVULNHUNTER_FRONTEND_PORT=%s\nVULNHUNTER_HOST=%s\n' \
  "$VULNHUNTER_PORT" "$VULNHUNTER_FRONTEND_PORT" "$VULNHUNTER_HOST" > "$PIDDIR/ports.env"

SHOW_HOST=$VULNHUNTER_HOST
case "$VULNHUNTER_HOST" in
  0.0.0.0|::) SHOW_HOST=127.0.0.1 ;;
esac

if [ -n "$VULNHUNTER_RELOAD" ]; then
  echo "[VulnHunter] backend  http://${SHOW_HOST}:${VULNHUNTER_PORT}  (reload)"
else
  echo "[VulnHunter] backend  http://${SHOW_HOST}:${VULNHUNTER_PORT}"
fi
case "$VULNHUNTER_HOST" in
  0.0.0.0) echo "[VulnHunter] listen   0.0.0.0 (LAN)" ;;
  ::) echo "[VulnHunter] listen   :: (LAN)" ;;
esac

nohup sh "$ROOT/scripts/_run-backend-inner.sh" >/dev/null 2>&1 &
echo $! > "$PIDDIR/backend.pid"

echo "[VulnHunter] frontend http://${SHOW_HOST}:${VULNHUNTER_FRONTEND_PORT}"
nohup sh "$ROOT/scripts/_run-frontend-inner.sh" >/dev/null 2>&1 &
echo $! > "$PIDDIR/frontend.pid"

echo "[VulnHunter] waiting for ports..."
n=0
ready=
while [ "$n" -lt 45 ]; do
  if port_listening "$VULNHUNTER_PORT" && port_listening "$VULNHUNTER_FRONTEND_PORT"; then
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
echo "  UI:   http://${SHOW_HOST}:${VULNHUNTER_FRONTEND_PORT}"
echo "  API:  http://${SHOW_HOST}:${VULNHUNTER_PORT}/docs"
case "$VULNHUNTER_HOST" in
  0.0.0.0|::)
    ips=
    if command -v ip >/dev/null 2>&1; then
      ips=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1) || true
    fi
    if [ -z "$ips" ] && command -v ifconfig >/dev/null 2>&1; then
      ips=$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1" {print $2}' | sed 's/addr://') || true
    fi
    for ip in $ips; do
      echo "  LAN UI:  http://${ip}:${VULNHUNTER_FRONTEND_PORT}"
      echo "  LAN API: http://${ip}:${VULNHUNTER_PORT}/docs"
    done
    echo "  Note: reachable on this network. Prefer VULNHUNTER_ACCESS_TOKEN."
    ;;
esac
echo "  Stop: sh stop.sh"
echo "  Dev:  sh start.sh --reload"
echo "  Ports: sh start.sh --backend-port N --frontend-port N"
echo "  LAN:   sh start.sh --lan   (or --host 0.0.0.0)"
echo "  Logs: data/logs/"
echo
