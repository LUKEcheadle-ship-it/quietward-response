#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.action_registry import ACTION_REGISTRY
from app.services.response_plan import build_response_plan


CASES = (
    ("malware_signature", "malware", "critical", "malware"),
    ("privilege_escalation", "privilege", "high", "privilege"),
    ("auth_failure", "identity", "medium", "identity"),
    ("persistence_change", "persistence", "high", "persistence"),
    ("outbound_connection", "network", "high", "network"),
    ("container_escape_indicator", "container", "critical", "container"),
    ("package_vulnerability", "vulnerability", "medium", "vulnerability"),
    ("evidence_integrity_failure", "integrity", "critical", "integrity"),
)


def main() -> int:
    actual = set(ACTION_REGISTRY)
    if actual != {"restart_quietward_demo_service"}:
        raise RuntimeError(f"unexpected executable alpha action surface: {sorted(actual)}")

    forbidden_fragments = ("shell", "command", "exec", "powershell", "script")
    for action_type in actual:
        if any(fragment in action_type.lower() for fragment in forbidden_fragments):
            raise RuntimeError(f"generic execution surface detected: {action_type}")

    for index, (event_type, category, severity, expected_family) in enumerate(CASES):
        incident = SimpleNamespace(
            incident_id=f"alpha-static-{index}",
            severity=severity,
        )
        event = SimpleNamespace(event_type=event_type, category=category)
        plan = build_response_plan(incident, [event])
        if expected_family not in plan["attack_families"]:
            raise RuntimeError(f"missing response family {expected_family}: {plan!r}")
        if plan["executable_actions"]:
            raise RuntimeError(
                f"non-demo response plan unexpectedly executable: {plan['executable_actions']}"
            )
        if not plan["investigation_steps"]:
            raise RuntimeError(f"response plan has no investigation steps: {expected_family}")
        for section in ("containment_steps", "recovery_steps"):
            for step in plan[section]:
                if step.get("state") not in {"available", "manual", "planned", "blocked"}:
                    raise RuntimeError(f"invalid step state: {step!r}")

    demo_incident = SimpleNamespace(incident_id="alpha-demo", severity="medium")
    demo_event = SimpleNamespace(event_type="demo_service_unhealthy", category="operational")
    demo_plan = build_response_plan(demo_incident, [demo_event])
    if demo_plan["executable_actions"] != ["restart_quietward_demo_service"]:
        raise RuntimeError(f"demo action missing from demo plan: {demo_plan!r}")

    print("V1.1 ALPHA RESPONSE PLAN SURFACE: PASS")
    print("Executable endpoint actions: restart_quietward_demo_service")
    print("Advisory response families:", ", ".join(case[3] for case in CASES))
    print("Generic command/shell execution surface: absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
