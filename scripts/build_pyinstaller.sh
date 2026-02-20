#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "pyinstaller 未安装，请先执行: pip install pyinstaller"
  exit 1
fi

rm -rf dist build flux.spec
pyinstaller \
  --name flux-xdr \
  --onefile \
  --add-data "frontend:frontend" \
  --paths backend \
  backend/run_app.py

echo "构建完成: dist/flux-xdr"
