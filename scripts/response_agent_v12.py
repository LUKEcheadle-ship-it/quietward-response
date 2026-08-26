from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import stat
from pathlib import Path
from typing import Any

try:
    import response_agent as base
    import response_agent_resources as resources_module
    from private_state_io import (
        PrivateStateError,
        atomic_private_json,
        load_private_json,
    )
    from response_agent import ResponseAgentError
    from response_agent_file_v12 import collect_file_diagnostic as collect_file_diagnostic_v12
    from response_agent_network import collect_network_diagnostic
except ImportError:  # package-style test import
    from scripts import response_agent as base
    from scripts import response_agent_resources as resources_module
    from scripts.private_state_io import (
        PrivateStateError,
        atomic_private_json,
        load_private_json,
    )
    from scripts.response_agent import ResponseAgentError
    from scripts.response_agent_file_v12 import collect_file_diagnostic as collect_file_diagnostic_v12
    from scripts.response_agent_network import collect_network_diagnostic

_MAX_AGENT_CONFIG_BYTES = 64 * 1024
_MAX_RUNTIME_STATE_BYTES = 64 * 1024 * 1024


def _secure_agent_state_load(path: Path, expected_type: type) -> Any:
    try:
        return load_private_json(
            path,
            expected_type,
            max_bytes=_MAX_RUNTIME_STATE_BYTES,
        )
    except PrivateStateError as exc:
        raise ResponseAgentError(
            f"agent state is unreadable or unsafe: {path.name}"
        ) from exc


def _secure_resource_mapping(path: Path) -> dict[str, dict[str, Any]]:
    try:
        value = load_private_json(
            path,
            dict,
            max_bytes=_MAX_RUNTIME_STATE_BYTES,
        )
    except PrivateStateError as exc:
        raise resources_module.ResourceError(
            f"resource handle state is unreadable or unsafe: {path.name}"
        ) from exc
    if any(not isinstance(item, dict) for item in value.values()):
        raise resources_module.ResourceError(
            "resource handle state has invalid structure"
        )
    return value


# The canonical v1.2 runtime upgrades the v1 agent's local state I/O without
# duplicating the large execution engine. Module globals are resolved at call
# time, so the existing ledger/demo/handle code now uses these hardened helpers.
base._atomic_json = atomic_private_json
base._load_json = _secure_agent_state_load
resources_module._atomic_json = atomic_private_json
resources_module._load_mapping = _secure_resource_mapping


def _private_config_path(path: Path) -> Path:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise ResponseAgentError("Response agent config path must be absolute")
    if resolved.is_symlink():
        raise ResponseAgentError("Response agent config must not be a symbolic link")
    try:
        info = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise ResponseAgentError(f"Response agent config file is unavailable: {resolved}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ResponseAgentError("Response agent config must be a regular file")
    if info.st_size <= 0 or info.st_size > _MAX_AGENT_CONFIG_BYTES:
        raise ResponseAgentError("Response agent config size is invalid")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ResponseAgentError("Response agent config must not be group/world accessible")
    return resolved


class AgentConfig(base.AgentConfig):
    """v1.2 config loader that enforces the credential-file boundary at runtime."""

    @classmethod
    def from_file(cls, path: Path) -> "AgentConfig":
        resolved = _private_config_path(path)
        try:
            value = load_private_json(
                resolved,
                dict,
                max_bytes=_MAX_AGENT_CONFIG_BYTES,
            )
        except PrivateStateError as exc:
            raise ResponseAgentError(
                "Response agent config is unreadable or unsafe"
            ) from exc
        return cls.from_mapping(value)


base._ACTION_PARAMETER_MODE.setdefault("collect_network_diagnostic", "none")


def _process_termination_supported() -> bool:
    system = platform.system().lower()
    if system == "windows":
        return True
    if system != "linux":
        return False
    return hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")


class ResponseAgent(base.ResponseAgent):
    """Canonical v1.2 Response agent with bounded typed diagnostics/containment."""

    def capabilities(self) -> dict[str, Any]:
        value = super().capabilities()
        system = platform.system().lower()
        read_only = [str(item) for item in value.get("read_only_actions", [])]
        if system == "linux" and "collect_network_diagnostic" not in read_only:
            read_only.append("collect_network_diagnostic")
        if system not in {"linux", "windows"}:
            read_only = [
                item
                for item in read_only
                if item not in {"collect_process_diagnostic", "collect_file_diagnostic"}
            ]
        value["read_only_actions"] = read_only

        mutating = {
            str(key): bool(enabled)
            for key, enabled in dict(value.get("mutating_actions", {})).items()
        }
        mutating["terminate_process_by_handle"] = bool(
            mutating.get("terminate_process_by_handle")
            and _process_termination_supported()
        )
        managed_file_supported = bool(
            system in {"linux", "windows"} and self.config.managed_roots
        )
        mutating["quarantine_artifact_by_handle"] = bool(
            mutating.get("quarantine_artifact_by_handle") and managed_file_supported
        )
        mutating["restore_quarantined_artifact_by_handle"] = bool(
            mutating.get("restore_quarantined_artifact_by_handle")
            and managed_file_supported
        )
        value["mutating_actions"] = mutating
        value["runtime_platform"] = system
        value["safe_process_termination_supported"] = _process_termination_supported()
        return value

    def _execute_action(
        self,
        action: dict[str, Any],
        *,
        recover_after_started: bool,
    ) -> dict[str, Any]:
        action_type = str(action.get("action_type"))
        if action_type == "collect_network_diagnostic":
            if platform.system().lower() != "linux":
                raise ResponseAgentError("network diagnostic is supported only on Linux")
            try:
                return collect_network_diagnostic(self.resources)
            except Exception as exc:
                if isinstance(exc, ResponseAgentError):
                    raise
                raise ResponseAgentError(str(exc)) from exc
        if action_type == "collect_file_diagnostic":
            if platform.system().lower() not in {"linux", "windows"}:
                raise ResponseAgentError("file diagnostics are qualified only on Linux and Windows")
            try:
                return collect_file_diagnostic_v12(
                    self.resources,
                    self.config.managed_roots,
                )
            except Exception as exc:
                if isinstance(exc, ResponseAgentError):
                    raise
                raise ResponseAgentError(str(exc)) from exc
        return super()._execute_action(
            action,
            recover_after_started=recover_after_started,
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect the canonical QuietWard Response v1.2 agent capability surface."
    )
    parser.add_argument("command", choices=("capabilities",))
    parser.add_argument("--config", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    config = AgentConfig.from_file(args.config.expanduser())
    agent = ResponseAgent(config)
    print(json.dumps(agent.capabilities(), indent=2, sort_keys=True))
    return 0


__all__ = ["AgentConfig", "ResponseAgent", "ResponseAgentError"]


if __name__ == "__main__":
    raise SystemExit(main())
