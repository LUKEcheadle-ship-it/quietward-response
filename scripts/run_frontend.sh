#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}/frontend"

if [[ ! -d node_modules ]]; then
  npm ci
fi
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js 22 or newer is required." >&2
  exit 1
fi

# Next.js does not automatically load the repository-root .env when it is started
# from frontend/. Resolve the public API URL here so QWR_API_PORT and browser
# configuration cannot silently diverge.
API_PORT="${QWR_API_PORT:-}"
if [[ -z "${API_PORT}" && -f "${ROOT}/.env" ]]; then
  API_PORT="$(sed -n 's/^QWR_API_PORT=//p' "${ROOT}/.env" | tail -n 1 | tr -d '[:space:]')"
fi
API_PORT="${API_PORT:-8002}"
if [[ ! "${API_PORT}" =~ ^[0-9]+$ ]] || (( API_PORT < 1 || API_PORT > 65535 )); then
  echo "QWR_API_PORT must be a valid TCP port." >&2
  exit 1
fi

if [[ -z "${NEXT_PUBLIC_API_URL:-}" && -f "${ROOT}/.env" ]]; then
  FILE_API_URL="$(sed -n 's/^NEXT_PUBLIC_API_URL=//p' "${ROOT}/.env" | tail -n 1 | tr -d '[:space:]')"
  # Older local .env files may still contain the former example default. If the
  # API port changed but that untouched default did not, follow QWR_API_PORT.
  if [[ "${API_PORT}" != "8002" && ( "${FILE_API_URL}" == "http://localhost:8002" || "${FILE_API_URL}" == "http://127.0.0.1:8002" ) ]]; then
    FILE_API_URL=""
  fi
  NEXT_PUBLIC_API_URL="${FILE_API_URL}"
fi
NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-http://localhost:${API_PORT}}"
export NEXT_PUBLIC_API_URL
export NEXT_TELEMETRY_DISABLED=1

NEXT_CLI="${ROOT}/frontend/node_modules/next/dist/bin/next"
if [[ ! -f "${NEXT_CLI}" ]]; then
  echo "Next.js CLI was not installed correctly." >&2
  exit 1
fi

# Execute the Next process directly rather than keeping an npm parent process.
# This lets run_all.sh terminate the actual server deterministically on shutdown.
exec node "${NEXT_CLI}" dev -H 127.0.0.1 -p 3001
