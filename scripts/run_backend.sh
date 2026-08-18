#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python -m uvicorn app.main:app --app-dir backend --host "${API_HOST:-0.0.0.0}" --port "${API_PORT:-8001}" --reload
