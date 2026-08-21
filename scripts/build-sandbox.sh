#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT"
if ! docker build -t vulnhunter/sandbox:latest docker/sandbox; then
  echo "构建失败。请确认 Docker 已启动。"
  exit 1
fi
echo "已构建 vulnhunter/sandbox:latest"
