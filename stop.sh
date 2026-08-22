#!/bin/sh
# Stop backend + frontend (default ports 16780 / 15173; last-used ports in data/run/ports.env).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$ROOT/scripts/stop.sh" "$@"
