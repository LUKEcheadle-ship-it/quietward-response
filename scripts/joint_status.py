#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from response_agent import AgentConfig


def _json_get(url: str, timeout: float) -> Any:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"GET {url} -> HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise RuntimeError(f"GET {url} failed: {exc}") from exc
    return json.loads(raw) if raw else None


def _ledger(config: AgentConfig) -> dict[str, dict[str, Any]]:
    path = config.state_dir / "quietward-handoff-consumption-ledger.json"
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("handoff consumption ledger is unreadable") from exc
    if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
        raise RuntimeError("handoff consumption ledger is invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Show joint QuietWard / Response bridge status")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    config = AgentConfig.from_file(args.config)
    inbox = args.inbox.expanduser().resolve()
    if not inbox.is_dir() or inbox.is_symlink():
        raise RuntimeError(f"handoff inbox is unavailable or unsafe: {inbox}")
    archive = inbox / "processed"
    ledger = _ledger(config)
    ordered = sorted(
        ledger.items(),
        key=lambda item: str(item[1].get("processed_at") or ""),
        reverse=True,
    )
    last_name, last_entry = ordered[0] if ordered else (None, None)

    api_health = _json_get(config.base_url + "/health", config.timeout_seconds)
    agent = _json_get(
        config.base_url + f"/api/v1/agents/{config.agent_id}",
        config.timeout_seconds,
    )
    status = {
        "response_api": {
            "url": config.base_url,
            "health": api_health,
        },
        "response_agent": {
            "agent_id": config.agent_id,
            "host_id": config.host_id,
            "enabled": bool(agent.get("enabled")) if isinstance(agent, dict) else None,
            "agent_version": agent.get("agent_version") if isinstance(agent, dict) else None,
            "enabled_actions": agent.get("enabled_actions", []) if isinstance(agent, dict) else [],
            "last_seen": agent.get("last_seen") if isinstance(agent, dict) else None,
        },
        "handoff_transport": {
            "inbox": str(inbox),
            "pending_files": len(list(inbox.glob("cycle-*.json"))),
            "archived_files": len(list(archive.glob("cycle-*.json"))) if archive.is_dir() else 0,
            "ledger_entries": len(ledger),
            "last_processed_file": last_name,
            "last_processed": last_entry,
        },
        "boundary": {
            "quietward_execution_authority": False,
            "response_arbitrary_command_execution": False,
            "transport": "local_private_handoff_files",
        },
    }
    print(json.dumps(status, indent=2 if args.pretty else None, sort_keys=True))
    healthy = (
        isinstance(api_health, dict)
        and api_health.get("status") == "ok"
        and isinstance(agent, dict)
        and agent.get("enabled") is True
    )
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
