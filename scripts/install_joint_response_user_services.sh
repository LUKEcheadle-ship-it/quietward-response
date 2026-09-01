#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_SCRIPT="$ROOT/scripts/response_agent.py"
WATCHER_SCRIPT="$ROOT/scripts/watch_quietward_handoffs.py"
CONFIG="${1:-}"
INBOX="${2:-}"
UNIT_DIR="$HOME/.config/systemd/user"
AGENT_UNIT="$UNIT_DIR/quietward-response-agent.service"
WATCHER_UNIT="$UNIT_DIR/quietward-response-handoff-watcher.service"

if [[ -z "$CONFIG" || -z "$INBOX" ]]; then
  echo "Usage: $0 /ABSOLUTE/PATH/agent-config.json /ABSOLUTE/PATH/quietward-response-handoff-outbox" >&2
  exit 2
fi
if [[ "$CONFIG" != /* || "$INBOX" != /* ]]; then
  echo "Agent config and handoff inbox paths must be absolute." >&2
  exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Response agent config not found: $CONFIG" >&2
  exit 2
fi
if [[ ! -d "$INBOX" ]]; then
  echo "QuietWard handoff inbox not found: $INBOX" >&2
  exit 2
fi
if [[ ! -f "$AGENT_SCRIPT" || ! -f "$WATCHER_SCRIPT" ]]; then
  echo "Response agent/watcher scripts are missing from this checkout." >&2
  exit 2
fi

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON="$ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  echo "python3 was not found." >&2
  exit 2
fi

mkdir -p "$UNIT_DIR"

cat >"$AGENT_UNIT" <<EOF
[Unit]
Description=QuietWard Response diagnostic endpoint agent
After=default.target

[Service]
Type=simple
ExecStart="$PYTHON" "$AGENT_SCRIPT" --config "$CONFIG" --interval 5
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
EOF

cat >"$WATCHER_UNIT" <<EOF
[Unit]
Description=QuietWard Response handoff watcher
After=quietward-response-agent.service

[Service]
Type=simple
ExecStart="$PYTHON" "$WATCHER_SCRIPT" --config "$CONFIG" --inbox "$INBOX" --interval 5
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
UMask=0077

[Install]
WantedBy=default.target
EOF

chmod 600 "$AGENT_UNIT" "$WATCHER_UNIT"
systemctl --user daemon-reload
systemctl --user enable --now quietward-response-agent.service quietward-response-handoff-watcher.service

echo "QuietWard Response joint user services installed."
echo "Agent unit: $AGENT_UNIT"
echo "Watcher unit: $WATCHER_UNIT"
echo "Inbox: $INBOX"
echo "Status: systemctl --user status quietward-response-agent.service quietward-response-handoff-watcher.service"
