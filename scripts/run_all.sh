#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  :
elif command -v python3 >/dev/null && python3 -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null; then
  PYTHON_BIN=python3
elif command -v python >/dev/null && python -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null; then
  PYTHON_BIN=python
else
  echo "Python 3.12 or newer is required." >&2
  exit 1
fi
export PYTHON_BIN

API_PORT="${QWR_API_PORT:-8002}"
API_URL="http://127.0.0.1:${API_PORT}"

./scripts/run_backend.sh &
BACKEND_PID=$!
./scripts/run_frontend.sh &
FRONTEND_PID=$!

cleanup() {
  kill "${BACKEND_PID}" "${FRONTEND_PID}" 2>/dev/null || true
  wait "${BACKEND_PID}" "${FRONTEND_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 60); do
  if curl --fail --silent "${API_URL}/health" >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl --fail --silent "${API_URL}/health" >/dev/null; then
  echo "Backend did not become healthy within 60 seconds." >&2
  exit 1
fi

# v1 no longer pollutes a normal startup with synthetic incidents. Opt in when
# demonstrating the original Phase 1 scenarios.
case "${QWR_SEED_DEMO:-false}" in
  1|true|TRUE|yes|YES|on|ON)
    "${PYTHON_BIN}" "${ROOT}/scripts/seed_demo.py" --api-url "${API_URL}"
    ;;
esac

cat <<EOF

QuietWard Response is ready.
Frontend: http://localhost:3001
API:      http://localhost:${API_PORT}
API docs: http://localhost:${API_PORT}/docs

Set QWR_SEED_DEMO=true before startup only when you want the three synthetic demo incidents.
Press Ctrl+C to stop both services.
EOF

wait
