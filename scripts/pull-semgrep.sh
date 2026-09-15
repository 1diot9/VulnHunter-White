#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT"
if ! docker pull returntocorp/semgrep:latest; then
  echo "拉取失败。请确认 Docker 已启动，且能访问镜像仓库。"
  exit 1
fi
echo "已拉取 returntocorp/semgrep:latest"
