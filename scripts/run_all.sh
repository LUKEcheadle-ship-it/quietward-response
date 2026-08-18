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

# run_backend.sh loads repository-root .env through the Pydantic settings layer.
# Resolve the same simple numeric port here so health checks do not accidentally
# keep probing the default when .env selected a different local port.
API_PORT="${QWR_API_PORT:-}"
if [[ -z "${API_PORT}" && -f "${ROOT}/.env" ]]; then
  API_PORT="$(sed -n 's/^QWR_API_PORT=//p' "${ROOT}/.env" | tail -n 1 | tr -d '[:space:]')"
fi
API_PORT="${API_PORT:-8002}"
if [[ ! "${API_PORT}" =~ ^[0-9]+$ ]] || (( API_PORT < 1 || API_PORT > 65535 )); then
  echo "QWR_API_PORT must be a valid TCP port." >&2
  exit 1
fi
API_URL="http://127.0.0.1:${API_PORT}"
FRONTEND_URL="http://127.0.0.1:3001"

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
  if ! kill -0 "${BACKEND_PID}" 2>/dev/null; then
    echo "Backend exited before becoming healthy." >&2
    exit 1
  fi
  if curl --fail --silent "${API_URL}/health" >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl --fail --silent "${API_URL}/health" >/dev/null; then
  echo "Backend did not become healthy within 60 seconds." >&2
  exit 1
fi

for _ in $(seq 1 60); do
  if ! kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    echo "Frontend exited before becoming reachable." >&2
    exit 1
  fi
  if curl --fail --silent "${FRONTEND_URL}/" >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl --fail --silent "${FRONTEND_URL}/" >/dev/null; then
  echo "Frontend did not become reachable within 60 seconds." >&2
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
