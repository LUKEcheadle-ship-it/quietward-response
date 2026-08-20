#!/usr/bin/env python3
from __future__ import annotations

from app.services.action_registry import ACTION_REGISTRY


DIAGNOSTIC_ACTIONS = {
    "collect_process_diagnostic",
    "collect_network_diagnostic",
    "collect_persistence_diagnostic",
    "collect_file_diagnostic",
    "collect_container_diagnostic",
    "collect_identity_diagnostic",
    "collect_vulnerability_diagnostic",
    "collect_integrity_diagnostic",
}
EXPECTED_ACTIONS = {"restart_quietward_demo_service", *DIAGNOSTIC_ACTIONS}


def main() -> int:
    actual = set(ACTION_REGISTRY)
    if actual != EXPECTED_ACTIONS:
        raise RuntimeError(
            f"unexpected v1.1 response action surface: {sorted(actual)}"
        )

    for action_type in sorted(DIAGNOSTIC_ACTIONS):
        definition = ACTION_REGISTRY[action_type]
        if definition.approval_required is not True:
            raise RuntimeError(f"{action_type} must require approval")
        if definition.risk_level != "low":
            raise RuntimeError(f"{action_type} must remain low risk")
        if definition.reversible is not True:
            raise RuntimeError(f"{action_type} must remain reversible/read-only")
        if definition.validate_parameters({}) != []:
            raise RuntimeError(f"{action_type} rejected its empty parameter envelope")
        if not definition.validate_parameters({"command": "forbidden"}):
            raise RuntimeError(f"{action_type} accepted non-empty parameters")

    forbidden_fragments = ("shell", "command", "exec", "powershell", "script")
    for action_type in actual:
        if any(fragment in action_type.lower() for fragment in forbidden_fragments):
            raise RuntimeError(f"generic execution surface detected: {action_type}")

    print("V1.1 DIAGNOSTIC RESPONSE SURFACE: PASS")
    print("Approval-gated diagnostics:", ", ".join(sorted(DIAGNOSTIC_ACTIONS)))
    print("Legacy v1 demo action retained: restart_quietward_demo_service")
    print("Generic command/shell execution surface: absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
