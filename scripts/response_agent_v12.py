from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

try:
    import response_agent as base
    from response_agent import AgentConfig, ResponseAgentError
    from response_agent_network import collect_network_diagnostic
except ImportError:  # package-style test import
    from scripts import response_agent as base
    from scripts.response_agent import AgentConfig, ResponseAgentError
    from scripts.response_agent_network import collect_network_diagnostic

# Extend the finite v1.2 agent protocol with one additional read-only action.
# The base class continues to own auth, approval/policy validation, exactly-once
# execution, result signing, handle provenance, and mutating executors.
base._ACTION_PARAMETER_MODE.setdefault("collect_network_diagnostic", "none")


class ResponseAgent(base.ResponseAgent):
    """Canonical v1.2 Response agent including bounded Linux network diagnostics."""

    def capabilities(self) -> dict[str, Any]:
        value = super().capabilities()
        read_only = [str(item) for item in value.get("read_only_actions", [])]
        if platform.system().lower() == "linux" and "collect_network_diagnostic" not in read_only:
            read_only.append("collect_network_diagnostic")
        value["read_only_actions"] = read_only
        return value

    def _execute_action(
        self,
        action: dict[str, Any],
        *,
        recover_after_started: bool,
    ) -> dict[str, Any]:
        if str(action.get("action_type")) == "collect_network_diagnostic":
            try:
                return collect_network_diagnostic(self.resources)
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
