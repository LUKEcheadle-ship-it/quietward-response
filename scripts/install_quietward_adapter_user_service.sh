#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
  echo "Run this installer as the normal user, not root." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
agent_config="${1:-${HOME}/.config/quietward-response/agent.json}"
quietward_db="${2:-${HOME}/.local/state/quietward/quietward.sqlite3}"
adapter_config="${3:-${HOME}/.config/quietward-response/adapter.json}"
install_root="${HOME}/.local/share/quietward-response-agent"
state_root="${HOME}/.local/state/quietward-response-agent"
unit_dir="${HOME}/.config/systemd/user"
unit_path="${unit_dir}/quietward-response-quietward-adapter.service"

for path in "${agent_config}" "${quietward_db}" "${adapter_config}"; do
  case "${path}" in
    /*) ;;
    *) echo "Path must be absolute: ${path}" >&2; exit 2 ;;
  esac
done

if [[ -L "${agent_config}" || ! -f "${agent_config}" ]]; then
  echo "Response agent config must exist as a normal file: ${agent_config}" >&2
  exit 2
fi
mode_text="$(stat -c '%a' "${agent_config}")"
mode=$((8#${mode_text}))
if (( mode & 077 )); then
  echo "Response agent config must not be group/world accessible: ${agent_config}" >&2
  exit 2
fi
if [[ -L "${quietward_db}" || ! -f "${quietward_db}" ]]; then
  echo "QuietWard database must exist as a normal file: ${quietward_db}" >&2
  exit 2
fi

mkdir -p "${install_root}" "${state_root}" "${unit_dir}" "$(dirname "${adapter_config}")"
chmod 700 "${install_root}" "${state_root}" "${unit_dir}" "$(dirname "${adapter_config}")"

python3 "${repo_root}/scripts/provision_quietward_adapter.py" \
  --agent-config "${agent_config}" \
  --adapter-config "${adapter_config}" \
  --force >/dev/null
chmod 600 "${adapter_config}"

runtime_files=(
  forward_quietward_events.py
  quietward_adapter_credentials.py
  reloading_adapter_client.py
)
for file in "${runtime_files[@]}"; do
  install -m 700 "${repo_root}/scripts/${file}" "${install_root}/${file}"
done

python3 "${install_root}/forward_quietward_events.py" \
  --config "${adapter_config}" \
  --quietward-db "${quietward_db}" \
  --once >/dev/null

sed \
  -e "s|%h/.config/quietward-response/adapter.json|${adapter_config}|g" \
  -e "s|%h/.local/state/quietward/quietward.sqlite3|${quietward_db}|g" \
  "${repo_root}/deploy/quietward-response-quietward-adapter.service" > "${unit_path}"
chmod 600 "${unit_path}"

systemctl --user daemon-reload
systemctl --user enable --now quietward-response-quietward-adapter.service
if ! systemctl --user is-active --quiet quietward-response-quietward-adapter.service; then
  echo "QuietWard Response adapter did not become active." >&2
  systemctl --user --no-pager status quietward-response-quietward-adapter.service >&2 || true
  exit 1
fi

echo "QuietWard to Response adapter service installed and active."
echo "QuietWard database (read-only): ${quietward_db}"
echo "Adapter credential (event-only): ${adapter_config}"
