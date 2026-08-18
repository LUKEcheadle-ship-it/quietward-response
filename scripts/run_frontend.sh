#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/frontend"

if [[ ! -d node_modules ]]; then
  npm ci
fi

export NEXT_TELEMETRY_DISABLED=1
exec npm run dev
