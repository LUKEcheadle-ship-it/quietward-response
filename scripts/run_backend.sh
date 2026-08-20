#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
VENV_DIR="${QWR_VENV_DIR:-${ROOT}/.venv}"

if [[ ! -x "${VENV_DIR}/bin/python" && ! -x "${VENV_DIR}/Scripts/python.exe" ]]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

if [[ -x "${VENV_DIR}/bin/python" ]]; then
  VENV_PYTHON="${VENV_DIR}/bin/python"
else
  VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
fi

"${VENV_PYTHON}" -m pip install -q -r "${ROOT}/backend/requirements.txt"
cd "${ROOT}/backend"
"${VENV_PYTHON}" -m alembic upgrade head

# Resolve bind settings through the same Pydantic settings loader as the API and
# Alembic. This makes repository-root .env values effective for the launcher too.
API_HOST="$("${VENV_PYTHON}" -c 'from app.config import get_settings; print(get_settings().api_host)')"
API_PORT="$("${VENV_PYTHON}" -c 'from app.config import get_settings; print(get_settings().api_port)')"

exec "${VENV_PYTHON}" -m uvicorn app.main:runtime_app \
  --factory \
  --host "${API_HOST}" \
  --port "${API_PORT}" \
  --workers 1
