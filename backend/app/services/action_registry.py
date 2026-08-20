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
        # The first expanded response surface deliberately remains parameter-free.
        # This keeps the server from turning a diagnostic action into a generic
        # process/path/network selector before endpoint-side identity binding exists.
        if parameters:
            return ["this action accepts no parameters"]
        return []


SUPPORTED_DIAGNOSTIC_OS = ("linux", "windows", "unknown")


def _diagnostic(action_type: str, description: str) -> ActionDefinition:
    return ActionDefinition(
        action_type=action_type,
        description=description,
        risk_level="low",
        approval_required=True,
        supported_os=SUPPORTED_DIAGNOSTIC_OS,
        reversible=True,
        implementation_version="1",
    )


RESTART_QUIETWARD_DEMO_SERVICE = ActionDefinition(
    action_type="restart_quietward_demo_service",
    description="Reset only the dedicated QuietWard Response JSON demo fixture to its healthy state.",
    risk_level="low",
    approval_required=True,
    supported_os=("linux", "windows", "darwin", "unknown"),
    reversible=True,
    implementation_version="1",
)

COLLECT_PROCESS_DIAGNOSTIC = _diagnostic(
    "collect_process_diagnostic",
    "Collect a bounded read-only process snapshot and process/privilege events from QuietWard.",
)
COLLECT_NETWORK_DIAGNOSTIC = _diagnostic(
    "collect_network_diagnostic",
    "Collect bounded read-only listening-socket and outbound-connection context from QuietWard.",
)
COLLECT_PERSISTENCE_DIAGNOSTIC = _diagnostic(
    "collect_persistence_diagnostic",
    "Collect bounded read-only persistence inventory and persistence-change context from QuietWard.",
)
COLLECT_FILE_DIAGNOSTIC = _diagnostic(
    "collect_file_diagnostic",
    "Collect bounded read-only file integrity, executable, malware-signature, and YARA context from QuietWard.",
)
COLLECT_CONTAINER_DIAGNOSTIC = _diagnostic(
    "collect_container_diagnostic",
    "Collect bounded read-only container state and container security-change context from QuietWard.",
)
COLLECT_IDENTITY_DIAGNOSTIC = _diagnostic(
    "collect_identity_diagnostic",
    "Collect bounded authentication, account-change, and privilege-escalation context already observed by QuietWard.",
)
COLLECT_VULNERABILITY_DIAGNOSTIC = _diagnostic(
    "collect_vulnerability_diagnostic",
    "Collect bounded package-vulnerability and configuration-weakness context already observed by QuietWard.",
)
COLLECT_INTEGRITY_DIAGNOSTIC = _diagnostic(
    "collect_integrity_diagnostic",
    "Collect bounded QuietWard self-integrity, evidence-integrity, and collector-health context.",
)

ACTION_REGISTRY: dict[str, ActionDefinition] = {
    item.action_type: item
    for item in (
        RESTART_QUIETWARD_DEMO_SERVICE,
        COLLECT_PROCESS_DIAGNOSTIC,
        COLLECT_NETWORK_DIAGNOSTIC,
        COLLECT_PERSISTENCE_DIAGNOSTIC,
        COLLECT_FILE_DIAGNOSTIC,
        COLLECT_CONTAINER_DIAGNOSTIC,
        COLLECT_IDENTITY_DIAGNOSTIC,
        COLLECT_VULNERABILITY_DIAGNOSTIC,
        COLLECT_INTEGRITY_DIAGNOSTIC,
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
