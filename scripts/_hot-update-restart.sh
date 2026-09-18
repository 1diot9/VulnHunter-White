#!/bin/sh
# Spawned by the backend after a successful git fast-forward. Waits for the
# API response to flush, then stop + start with the same listen settings.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

sleep 3
sh "$ROOT/stop.sh" --quiet

args=
case "${VULNHUNTER_RELOAD:-}" in
  ''|0|false|FALSE|no|NO) ;;
  *) args="$args --reload" ;;
esac
if [ -n "${VULNHUNTER_HOST:-}" ]; then
  args="$args --host $VULNHUNTER_HOST"
fi
if [ -n "${VULNHUNTER_PORT:-}" ]; then
  args="$args --backend-port $VULNHUNTER_PORT"
fi
if [ -n "${VULNHUNTER_FRONTEND_PORT:-}" ]; then
  args="$args --frontend-port $VULNHUNTER_FRONTEND_PORT"
fi

# shellcheck disable=SC2086
sh "$ROOT/start.sh" $args
