#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from response_agent import AgentConfig, ResponseAgent, ResponseAgentError, write_agent_config
from response_agent_capabilities import sync_capabilities


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rotate a Response-agent HMAC credential without printing the new secret."
    )
    parser.add_argument("--config", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    path = args.config.expanduser().resolve()
    current = AgentConfig.from_file(path)
    agent = ResponseAgent(current)
    target = f"/api/v1/agents/{current.agent_id}/rotate-key"
    value = agent._request("POST", target, {})
    if not isinstance(value, dict):
        raise ResponseAgentError("agent key rotation returned an invalid response")
    required = ("agent_id", "key_id", "secret", "previous_key_expires_at")
    if any(not value.get(key) for key in required):
        raise ResponseAgentError("agent key rotation response is missing required fields")
    if str(value["agent_id"]) != current.agent_id:
        raise ResponseAgentError("agent key rotation response targets another agent")
    if str(value["key_id"]) == current.key_id:
        raise ResponseAgentError("agent key rotation did not change the key identifier")

    rotated = AgentConfig(
        base_url=current.base_url,
        agent_id=current.agent_id,
        key_id=str(value["key_id"]),
        secret=str(value["secret"]),
        host_id=current.host_id,
        state_dir=current.state_dir,
        timeout_seconds=current.timeout_seconds,
        managed_roots=current.managed_roots,
        quarantine_dir=current.quarantine_dir,
        enable_process_termination=current.enable_process_termination,
        enable_file_quarantine=current.enable_file_quarantine,
    )
    write_agent_config(path, rotated, force=True)
    capability_state = sync_capabilities(ResponseAgent(rotated))

    print(f"Response agent key rotated: {rotated.agent_id}")
    print(f"New key ID: {rotated.key_id}")
    print(f"Previous key grace expires: {value['previous_key_expires_at']}")
    print(f"Private config updated atomically: {path}")
    print(f"New key verified by capability sync: {bool(capability_state.get('capabilities_updated_at'))}")
    print("The new agent secret was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
