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
        # The released QuietWard endpoint recognizes no arbitrary target/service/path
        # parameter. Keep the alpha endpoint-executed surface exactly compatible.
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

# Alpha rule: executable endpoint actions must remain compatible with the finished
# public QuietWard release. Broad cyber-response coverage lives in the response-plan
# engine until each future endpoint action has its own versioned typed contract.
ACTION_REGISTRY: dict[str, ActionDefinition] = {
    RESTART_QUIETWARD_DEMO_SERVICE.action_type: RESTART_QUIETWARD_DEMO_SERVICE,
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
