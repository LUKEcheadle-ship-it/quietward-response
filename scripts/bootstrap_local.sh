#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT}/.env"
EXAMPLE_FILE="${ROOT}/.env.example"
DEFAULT_TOKEN="development-enrollment-token-change-me"

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

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required. Install Node.js 22+ and npm, then rerun this script." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required." >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  cp "${EXAMPLE_FILE}" "${ENV_FILE}"
  chmod 600 "${ENV_FILE}" 2>/dev/null || true
  echo "Created .env from .env.example."
fi

CURRENT_TOKEN="$(sed -n 's/^QWR_ENROLLMENT_TOKEN=//p' "${ENV_FILE}" | tail -n 1)"
if [[ -z "${CURRENT_TOKEN}" || "${CURRENT_TOKEN}" == "${DEFAULT_TOKEN}" ]]; then
  NEW_TOKEN="$("${PYTHON_BIN}" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  "${PYTHON_BIN}" - "${ENV_FILE}" "${NEW_TOKEN}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
token = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
updated = []
replaced = False
for line in lines:
    if line.startswith("QWR_ENROLLMENT_TOKEN="):
        updated.append(f"QWR_ENROLLMENT_TOKEN={token}")
        replaced = True
    else:
        updated.append(line)
if not replaced:
    updated.append(f"QWR_ENROLLMENT_TOKEN={token}")
path.write_text("\n".join(updated) + "\n", encoding="utf-8")
PY
  chmod 600 "${ENV_FILE}" 2>/dev/null || true
  echo "Generated a private local enrollment token in .env."
fi

cd "${ROOT}"
exec ./scripts/run_all.sh
