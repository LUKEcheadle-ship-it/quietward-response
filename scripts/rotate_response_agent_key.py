#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from response_agent import AgentConfig, ResponseAgent, ResponseAgentError, write_agent_config
from response_agent_capabilities import sync_capabilities


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rotate a Response-agent HMAC credential without printing the new secret."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--recover-next",
        action="store_true",
        help="Recover a previously staged .next credential after an interrupted rotation.",
    )
    return parser


def _next_path(path: Path) -> Path:
    return path.with_name(path.name + ".next")


def _promote(next_path: Path, path: Path) -> None:
    os.replace(next_path, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _activate(agent: ResponseAgent) -> dict:
    target = f"/api/v1/agents/{agent.config.agent_id}/activate-key"
    value = agent._request("POST", target, {})
    if not isinstance(value, dict):
        raise ResponseAgentError("agent key activation returned an invalid response")
    if value.get("agent_id") != agent.config.agent_id:
        raise ResponseAgentError("agent key activation response targets another agent")
    if value.get("key_id") != agent.config.key_id:
        raise ResponseAgentError("agent key activation did not promote the staged key")
    return value


def _recover(path: Path, next_path: Path) -> int:
    if not next_path.exists():
        raise ResponseAgentError(f"no staged Response-agent credential exists: {next_path}")
    rotated = AgentConfig.from_file(next_path)
    rotated_agent = ResponseAgent(rotated)

    activation: dict | None = None
    try:
        capability_state = sync_capabilities(rotated_agent)
    except ResponseAgentError:
        activation = _activate(rotated_agent)
        capability_state = sync_capabilities(rotated_agent)

    _promote(next_path, path)
    print(f"Response agent key recovery completed: {rotated.agent_id}")
    print(f"Active key ID: {rotated.key_id}")
    if activation is not None:
        print(f"Previous key grace expires: {activation['previous_key_expires_at']}")
    print(f"Private config promoted atomically: {path}")
    print(f"New key verified by capability sync: {bool(capability_state.get('capabilities_updated_at'))}")
    print("The agent secret was not printed.")
    return 0


def main() -> int:
    args = _parser().parse_args()
    path = args.config.expanduser().resolve()
    next_path = _next_path(path)

    if args.recover_next:
        return _recover(path, next_path)
    if next_path.exists():
        raise ResponseAgentError(
            f"staged credential already exists: {next_path}; run with --recover-next before starting another rotation"
        )

    current = AgentConfig.from_file(path)
    current_agent = ResponseAgent(current)
    prepare_target = f"/api/v1/agents/{current.agent_id}/rotate-key"
    prepared = current_agent._request("POST", prepare_target, {})
    if not isinstance(prepared, dict):
        raise ResponseAgentError("agent key rotation preparation returned an invalid response")
    required = ("agent_id", "pending_key_id", "secret", "pending_key_expires_at")
    if any(not prepared.get(key) for key in required):
        raise ResponseAgentError("agent key rotation preparation is missing required fields")
    if str(prepared["agent_id"]) != current.agent_id:
        raise ResponseAgentError("agent key rotation preparation targets another agent")
    if str(prepared["pending_key_id"]) == current.key_id:
        raise ResponseAgentError("agent key rotation did not create a new key identifier")

    rotated = AgentConfig(
        base_url=current.base_url,
        agent_id=current.agent_id,
        key_id=str(prepared["pending_key_id"]),
        secret=str(prepared["secret"]),
        host_id=current.host_id,
        state_dir=current.state_dir,
        timeout_seconds=current.timeout_seconds,
        managed_roots=current.managed_roots,
        quarantine_dir=current.quarantine_dir,
        enable_process_termination=current.enable_process_termination,
        enable_file_quarantine=current.enable_file_quarantine,
    )

    # Persist the pending credential before activation. If activation or promotion is
    # interrupted, --recover-next can finish without exposing the secret.
    write_agent_config(next_path, rotated, force=False)
    rotated_agent = ResponseAgent(rotated)
    activation = _activate(rotated_agent)
    capability_state = sync_capabilities(rotated_agent)
    _promote(next_path, path)

    print(f"Response agent key rotated: {rotated.agent_id}")
    print(f"New key ID: {rotated.key_id}")
    print(f"Pending key deadline was: {prepared['pending_key_expires_at']}")
    print(f"Previous key grace expires: {activation['previous_key_expires_at']}")
    print(f"Private config updated atomically: {path}")
    print(f"New key verified by capability sync: {bool(capability_state.get('capabilities_updated_at'))}")
    print("The new agent secret was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
