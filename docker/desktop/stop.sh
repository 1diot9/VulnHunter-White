#!/bin/sh
# Docker edition: stop the app container.
# Usage: sh docker/desktop/stop.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
COMPOSE="$HERE/compose.yml"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
    return
  fi
  echo "[VulnHunter] docker compose not found. Install the Compose v2 plugin."
  exit 1
}

if ! compose -f "$COMPOSE" down; then
  echo "[VulnHunter] compose down failed."
  exit 1
fi
echo "[VulnHunter] Docker edition stopped."
