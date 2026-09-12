#!/bin/sh
# Docker edition: start the app container (Linux Engine / Docker Desktop).
# Usage: sh docker/desktop/start.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
COMPOSE="$HERE/compose.yml"
DATA="$ROOT/data"
mkdir -p "$DATA"

if ! command -v docker >/dev/null 2>&1; then
  echo "[VulnHunter] docker not found on PATH. Install Docker Engine (or Desktop) and retry."
  exit 1
fi

if ! docker version >/dev/null 2>&1; then
  echo "[VulnHunter] Docker engine not reachable."
  echo "  Start the service (e.g. sudo systemctl start docker) and ensure your user can run docker without sudo."
  echo "  Ubuntu/Debian: sudo usermod -aG docker \"\$USER\"  then log out and back in."
  exit 1
fi

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

if [ -z "${DOCKER_SOCK:-}" ]; then
  if [ -S /var/run/docker.sock ]; then
    DOCKER_SOCK=/var/run/docker.sock
  elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ]; then
    DOCKER_SOCK="$XDG_RUNTIME_DIR/docker.sock"
  elif [ -S "$HOME/.docker/run/docker.sock" ]; then
    DOCKER_SOCK="$HOME/.docker/run/docker.sock"
  else
    DOCKER_SOCK=/var/run/docker.sock
  fi
fi

if [ ! -S "$DOCKER_SOCK" ]; then
  echo "[VulnHunter] docker socket not found at $DOCKER_SOCK"
  echo "  Rootful: /var/run/docker.sock. Rootless: \$XDG_RUNTIME_DIR/docker.sock"
  exit 1
fi

sock_gid() {
  stat -c '%g' "$1" 2>/dev/null || stat -f '%g' "$1" 2>/dev/null || echo 0
}

VULNHUNTER_PORT="${VULNHUNTER_PORT:-16788}"
VULNHUNTER_HOST_DATA="$DATA"
VULNHUNTER_UID="${VULNHUNTER_UID:-$(id -u)}"
VULNHUNTER_GID="${VULNHUNTER_GID:-$(id -g)}"
DOCKER_GID="${DOCKER_GID:-$(sock_gid "$DOCKER_SOCK")}"
DOCKER_DATA_OPTS="${DOCKER_DATA_OPTS:-}"
DOCKER_SECURITY_OPT="${DOCKER_SECURITY_OPT:-no-new-privileges:false}"

if [ "$VULNHUNTER_UID" -eq 0 ]; then
  echo "[VulnHunter] WARN: running as root; files under data/ will be owned by root."
  echo "  Prefer a user in the docker group instead of sudo."
fi

if command -v getenforce >/dev/null 2>&1; then
  case "$(getenforce 2>/dev/null || true)" in
    Enforcing|Permissive)
      if [ -z "$DOCKER_DATA_OPTS" ]; then
        DOCKER_DATA_OPTS=:z
      fi
      if [ "$DOCKER_SECURITY_OPT" = "no-new-privileges:false" ]; then
        DOCKER_SECURITY_OPT=label:disable
      fi
      ;;
  esac
fi

export VULNHUNTER_PORT VULNHUNTER_HOST_DATA VULNHUNTER_UID VULNHUNTER_GID
export DOCKER_SOCK DOCKER_GID DOCKER_DATA_OPTS DOCKER_SECURITY_OPT
DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-1}"
export DOCKER_BUILDKIT

echo "[VulnHunter] Docker edition (Linux)"
echo "[VulnHunter] host data: $VULNHUNTER_HOST_DATA"
echo "[VulnHunter] UI/API:    http://127.0.0.1:$VULNHUNTER_PORT"
echo "[VulnHunter] docker sock: $DOCKER_SOCK (uid $VULNHUNTER_UID gid $DOCKER_GID)"
echo "[VulnHunter] first start may build sandbox images (several minutes)."
echo

if ! compose -f "$COMPOSE" up --build -d; then
  echo "[VulnHunter] compose up failed."
  exit 1
fi

echo
echo "[VulnHunter] started. Open http://127.0.0.1:$VULNHUNTER_PORT"
echo "[VulnHunter] logs: docker compose -f \"$COMPOSE\" logs -f"
echo "[VulnHunter] stop:  sh \"$HERE/stop.sh\""
