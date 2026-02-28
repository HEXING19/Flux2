#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$ROOT_DIR/backend"
python3 "$ROOT_DIR/scripts/migrate_db.py"
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
