#!/bin/bash
# Docker Desktop edition entrypoint: ensure sibling sandboxes, then start API+UI.
set -euo pipefail

echo "[VulnHunter] runtime=docker starting…"

# Persist data lives on the host bind at /data (symlinked to /app/data).
if [ -L /app/data ]; then
  :
elif [ -d /app/data ] && [ ! -L /app/data ]; then
  echo "[VulnHunter] WARN: /app/data is a real directory; replacing with symlink to /data"
  rm -rf /app/data
  ln -sfn /data /app/data
else
  ln -sfn /data /app/data
fi
mkdir -p /data/projects /data/logs /data/tmp /data/tools /data/run
# Seed showcase once if missing (same paths as demo_seed expects under data/).
if [ "${VULNHUNTER_DEMO_SEED:-1}" != "0" ] && [ ! -d /data/projects/11 ] && [ -d /app/data-seed/projects/11 ]; then
  echo "[VulnHunter] seeding showcase project 11 into /data/projects/11"
  mkdir -p /data/projects
  cp -a /app/data-seed/projects/11 /data/projects/11
fi

if [ ! -S /var/run/docker.sock ]; then
  echo "[VulnHunter] ERROR: /var/run/docker.sock not mounted."
  echo "  Docker Desktop must be running; compose must bind //var/run/docker.sock."
  exit 1
fi

if ! docker version >/dev/null 2>&1; then
  echo "[VulnHunter] ERROR: docker CLI cannot talk to the Desktop engine."
  docker version || true
  exit 1
fi

ensure_image() {
  local name="$1"
  local context="$2"
  if docker image inspect "$name" >/dev/null 2>&1; then
    echo "[VulnHunter] image present: $name"
    return 0
  fi
  echo "[VulnHunter] building $name (first run may take several minutes)…"
  docker build -t "$name" "$context"
  echo "[VulnHunter] built $name"
}

ensure_image "vulnhunter/sandbox:latest" "/app/docker/sandbox"
ensure_image "vulnhunter/integration-sandbox:latest" "/app/docker/integration-sandbox"

export VULNHUNTER_RUNTIME="${VULNHUNTER_RUNTIME:-docker}"
export VULNHUNTER_HOST="${VULNHUNTER_HOST:-0.0.0.0}"
export VULNHUNTER_PORT="${VULNHUNTER_PORT:-16788}"

echo "[VulnHunter] listening on ${VULNHUNTER_HOST}:${VULNHUNTER_PORT}"
exec python -m uvicorn app.main:app \
  --host "${VULNHUNTER_HOST}" \
  --port "${VULNHUNTER_PORT}" \
  --timeout-graceful-shutdown 2
