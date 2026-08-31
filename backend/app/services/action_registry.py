from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_type: str
    description: str
    risk_level: str
    approval_required: bool
    supported_os: tuple[str, ...]
    reversible: bool
    implementation_version: str

    def validate_parameters(self, parameters: dict[str, Any]) -> list[str]:
        # The current controlled surface deliberately exposes no arbitrary target,
        # service, path, PID, address, or command parameter. Diagnostic executors
        # determine their bounded local scope themselves.
        if parameters:
            return ["this action accepts no parameters"]
        return []


RESTART_QUIETWARD_DEMO_SERVICE = ActionDefinition(
    action_type="restart_quietward_demo_service",
    description="Reset only the dedicated QuietWard Response JSON demo fixture to its healthy state.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows", "darwin", "unknown"),
    reversible=True,
    implementation_version="1",
)

COLLECT_HOST_DIAGNOSTIC = ActionDefinition(
    action_type="collect_host_diagnostic",
    description="Collect a bounded read-only host and Response-agent health snapshot without running shell commands.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows", "darwin", "unknown"),
    reversible=True,
    implementation_version="2",
)

COLLECT_PROCESS_DIAGNOSTIC = ActionDefinition(
    action_type="collect_process_diagnostic",
    description="Collect a bounded read-only process inventory without command lines or arbitrary process targeting.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=True,
    implementation_version="2",
)

COLLECT_NETWORK_DIAGNOSTIC = ActionDefinition(
    action_type="collect_network_diagnostic",
    description="Collect a bounded read-only Linux network snapshot with remote addresses pseudonymized before leaving the endpoint.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux",),
    reversible=True,
    implementation_version="2",
)

ACTION_REGISTRY: dict[str, ActionDefinition] = {
    item.action_type: item
    for item in (
        RESTART_QUIETWARD_DEMO_SERVICE,
        COLLECT_HOST_DIAGNOSTIC,
        COLLECT_PROCESS_DIAGNOSTIC,
        COLLECT_NETWORK_DIAGNOSTIC,
    )
}


def get_action_definition(action_type: str) -> ActionDefinition | None:
    return ACTION_REGISTRY.get(action_type)


def public_action_registry() -> list[dict[str, object]]:
    return [
        {
            "action_type": item.action_type,
            "description": item.description,
            "risk_level": item.risk_level,
            "approval_required": item.approval_required,
            "supported_os": list(item.supported_os),
            "reversible": item.reversible,
            "implementation_version": item.implementation_version,
        }
        for item in ACTION_REGISTRY.values()
    ]
