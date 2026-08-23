#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
  echo "Run this installer as the normal Response-agent user, not root." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
config_path="${1:-${HOME}/.config/quietward-response/agent.json}"
install_root="${HOME}/.local/share/quietward-response-agent"
unit_dir="${HOME}/.config/systemd/user"
unit_path="${unit_dir}/quietward-response-agent.service"

case "${config_path}" in
  /*) ;;
  *) echo "Response agent config path must be absolute: ${config_path}" >&2; exit 2 ;;
esac

if [[ -L "${config_path}" || ! -f "${config_path}" ]]; then
  echo "Response agent config must exist as a normal file: ${config_path}" >&2
  exit 2
fi
mode_text="$(stat -c '%a' "${config_path}")"
mode=$((8#${mode_text}))
if (( mode & 077 )); then
  echo "Response agent config must not be group/world accessible: ${config_path}" >&2
  exit 2
fi

mkdir -p "${install_root}" "${unit_dir}"
chmod 700 "${install_root}" "${unit_dir}"

runtime_files=(
  poll_response_agent.py
  response_agent_v12.py
  response_agent.py
  response_agent_capabilities.py
  response_agent_network.py
  response_agent_resources.py
)
for file in "${runtime_files[@]}"; do
  install -m 700 "${repo_root}/scripts/${file}" "${install_root}/${file}"
done

python3 "${install_root}/response_agent_v12.py" capabilities --config "${config_path}" >/dev/null

sed \
  -e "s|%h/.config/quietward-response/agent.json|${config_path}|g" \
  "${repo_root}/deploy/quietward-response-agent.service" > "${unit_path}"
chmod 600 "${unit_path}"

systemctl --user daemon-reload
systemctl --user enable --now quietward-response-agent.service

if ! systemctl --user is-active --quiet quietward-response-agent.service; then
  echo "QuietWard Response agent did not become active." >&2
  systemctl --user --no-pager status quietward-response-agent.service >&2 || true
  exit 1
fi

echo "QuietWard Response agent service installed and active."
echo "Config: ${config_path}"
echo "Runtime: ${install_root}"
echo "Service: quietward-response-agent.service"
