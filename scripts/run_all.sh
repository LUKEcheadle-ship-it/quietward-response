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
  if curl --fail --silent http://127.0.0.1:8002/health >/dev/null; then
    break
  fi
  sleep 1
done

if ! curl --fail --silent http://127.0.0.1:8002/health >/dev/null; then
  echo "Backend did not become healthy within 60 seconds." >&2
  exit 1
fi

"${PYTHON_BIN}" "${ROOT}/scripts/seed_demo.py" --api-url http://127.0.0.1:8002

cat <<'EOF'

QuietWard Response is ready.
Frontend: http://localhost:3001
API:      http://localhost:8002
API docs: http://localhost:8002/docs

Press Ctrl+C to stop both services.
EOF

wait
