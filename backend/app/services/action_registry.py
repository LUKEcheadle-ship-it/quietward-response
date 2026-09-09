from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_PROCESS_HANDLE = re.compile(r"^qwrp-[0-9a-f]{32}$")


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
        if self.action_type == "terminate_evidence_process":
            if set(parameters) != {"evidence_handle"}:
                return ["terminate_evidence_process requires exactly one evidence_handle parameter"]
            handle = parameters.get("evidence_handle")
            if not isinstance(handle, str) or not _PROCESS_HANDLE.fullmatch(handle):
                return ["process evidence_handle is invalid"]
            return []
        # All other currently registered actions are deliberately parameterless.
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

COLLECT_INCIDENT_TRIAGE_BUNDLE = ActionDefinition(
    action_type="collect_incident_triage_bundle",
    description="Collect one bounded read-only incident triage bundle from host, process, and platform-supported privacy-preserving network diagnostics.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows", "darwin", "unknown"),
    reversible=True,
    implementation_version="2",
)

TERMINATE_EVIDENCE_PROCESS = ActionDefinition(
    action_type="terminate_evidence_process",
    description="Terminate only a process instance previously captured by the endpoint triage bundle and represented by an opaque evidence handle.",
    risk_level="high",
    approval_required=True,
    supported_os=("linux", "windows"),
    reversible=False,
    implementation_version="1",
)

ACTION_REGISTRY: dict[str, ActionDefinition] = {
    item.action_type: item
    for item in (
        RESTART_QUIETWARD_DEMO_SERVICE,
        COLLECT_HOST_DIAGNOSTIC,
        COLLECT_PROCESS_DIAGNOSTIC,
        COLLECT_NETWORK_DIAGNOSTIC,
        COLLECT_INCIDENT_TRIAGE_BUNDLE,
        TERMINATE_EVIDENCE_PROCESS,
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
