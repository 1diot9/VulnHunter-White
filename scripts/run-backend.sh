#!/bin/sh
# Kept for manual single-service debug; prefer ../start.sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
exec sh "$ROOT/scripts/_run-backend-inner.sh" "$@"
