from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


ParameterMode = Literal["none", "resource_handle"]


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_type: str
    description: str
    risk_level: str
    approval_required: bool
    supported_os: tuple[str, ...]
    reversible: bool
    implementation_version: str
    parameter_mode: ParameterMode = "none"
    max_ttl_seconds: int = 600

    def validate_parameters(self, parameters: dict[str, Any]) -> list[str]:
        if self.parameter_mode == "none":
            if parameters:
                return ["this action accepts no parameters"]
            return []

        if set(parameters) != {"resource_handle"}:
            return ["this action requires exactly one resource_handle parameter"]
        handle = parameters.get("resource_handle")
        if not isinstance(handle, str):
            return ["resource_handle must be a string"]
        if not handle.startswith("qwrh1_") or len(handle) < 16 or len(handle) > 96:
            return ["resource_handle format is invalid"]
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
    description="Collect a bounded read-only host/agent health snapshot without running shell commands.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows", "darwin", "unknown"),
    reversible=True,
    implementation_version="2",
)

COLLECT_PROCESS_DIAGNOSTIC = ActionDefinition(
    action_type="collect_process_diagnostic",
    description="Collect a bounded process snapshot and short-lived opaque process handles.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=True,
    implementation_version="2",
)

COLLECT_NETWORK_DIAGNOSTIC = ActionDefinition(
    action_type="collect_network_diagnostic",
    description="Collect a bounded Linux /proc network snapshot with endpoint-local keyed remote-address pseudonyms and short-lived opaque socket handles; raw network addresses are not returned.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux",),
    reversible=True,
    implementation_version="2",
)

TERMINATE_PROCESS_BY_HANDLE = ActionDefinition(
    action_type="terminate_process_by_handle",
    description="Terminate only the exact process identity represented by an unexpired agent-issued handle.",
    risk_level="high",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=False,
    implementation_version="2",
    parameter_mode="resource_handle",
    max_ttl_seconds=240,
)

COLLECT_FILE_DIAGNOSTIC = ActionDefinition(
    action_type="collect_file_diagnostic",
    description="Enumerate bounded regular files only within explicitly configured Response-agent managed roots and issue short-lived opaque handles.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=True,
    implementation_version="2",
)

QUARANTINE_ARTIFACT_BY_HANDLE = ActionDefinition(
    action_type="quarantine_artifact_by_handle",
    description="Move only the exact managed regular file represented by an unexpired agent-issued handle into the private Response quarantine directory.",
    risk_level="high",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=True,
    implementation_version="2",
    parameter_mode="resource_handle",
    max_ttl_seconds=240,
)

RESTORE_QUARANTINED_ARTIFACT_BY_HANDLE = ActionDefinition(
    action_type="restore_quarantined_artifact_by_handle",
    description="Restore a quarantined artifact only through the rollback handle created by the matching quarantine execution.",
    risk_level="medium",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=True,
    implementation_version="2",
    parameter_mode="resource_handle",
    max_ttl_seconds=600,
)


ACTION_REGISTRY: dict[str, ActionDefinition] = {
    item.action_type: item
    for item in (
        RESTART_QUIETWARD_DEMO_SERVICE,
        COLLECT_HOST_DIAGNOSTIC,
        COLLECT_PROCESS_DIAGNOSTIC,
        COLLECT_NETWORK_DIAGNOSTIC,
        TERMINATE_PROCESS_BY_HANDLE,
        COLLECT_FILE_DIAGNOSTIC,
        QUARANTINE_ARTIFACT_BY_HANDLE,
        RESTORE_QUARANTINED_ARTIFACT_BY_HANDLE,
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
            "parameter_mode": item.parameter_mode,
            "max_ttl_seconds": item.max_ttl_seconds,
        }
        for item in ACTION_REGISTRY.values()
    ]
