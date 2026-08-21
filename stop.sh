#!/bin/sh
# Stop backend + frontend (ports 8000 / 5173).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$ROOT/scripts/stop.sh" "$@"
