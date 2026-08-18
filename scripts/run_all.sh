#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ ! -d .venv ]]; then python -m venv .venv; fi
if [[ -f .venv/Scripts/activate ]]; then source .venv/Scripts/activate; else source .venv/bin/activate; fi
pip install -r backend/requirements.txt
./scripts/run_backend.sh & BACKEND_PID=$!
./scripts/run_frontend.sh & FRONTEND_PID=$!
trap 'kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null || true' EXIT INT TERM
wait
