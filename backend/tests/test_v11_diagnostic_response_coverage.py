from __future__ import annotations

import pytest

from app.services.action_registry import ACTION_REGISTRY


@pytest.mark.parametrize(
    ("event_type", "category", "severity", "expected_family"),
    [
        ("process_start", "execution", "medium", "execution"),
        ("privilege_escalation", "privilege", "high", "privilege"),
        ("malware_signature", "malware", "critical", "malware"),
        ("persistence_change", "persistence", "high", "persistence"),
        ("outbound_connection", "network", "high", "network"),
        ("container_escape_indicator", "container", "critical", "container"),
        ("auth_failure", "identity", "medium", "identity"),
        ("package_vulnerability", "vulnerability", "medium", "vulnerability"),
        ("evidence_integrity_failure", "integrity", "critical", "integrity"),
        ("service_unavailable", "operational", "medium", "operational"),
        # High-signal vendor vocabulary must flow through the same shared classifier
        # used by the public response-plan endpoint, even when the category is broad.
        ("ransomware_detected", "execution", "critical", "malware"),
        ("credential_spray_detected", "security", "high", "identity"),
        ("c2_beacon_detected", "security", "high", "network"),
        ("audit_log_clear", "security", "high", "integrity"),
        ("kubernetes_pod_security_violation", "security", "high", "container"),
        ("cve_2026_1234_detected", "security", "medium", "vulnerability"),
    ],
)
def test_major_attack_families_receive_structured_response_plans(
    client,
    event_factory,
    event_type: str,
    category: str,
    severity: str,
    expected_family: str,
) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=f"host-{expected_family}-{event_type}",
            event_type=event_type,
            category=category,
            severity=severity,
            summary=f"Synthetic {expected_family} evidence",
        ),
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident_id"]

    response = client.get(f"/api/v1/incidents/{incident_id}/response-plan")
    assert response.status_code == 200, response.text
    plan = response.json()

    assert plan["schema_version"] == "1.0"
    assert plan["mode"] == "advisory_with_controlled_actions"
    assert expected_family in plan["attack_families"]
    assert "unknown" not in plan["attack_families"]
    assert plan["investigation_steps"]
    assert plan["containment_steps"] or plan["recovery_steps"]
    assert plan["executable_actions"] == []
    assert all(
        step["state"] in {"available", "manual", "planned", "blocked"}
        for section in ("investigation_steps", "containment_steps", "recovery_steps")
        for step in plan[section]
    )


def test_executable_registry_remains_exactly_the_released_demo_surface() -> None:
    assert set(ACTION_REGISTRY) == {"restart_quietward_demo_service"}
    definition = ACTION_REGISTRY["restart_quietward_demo_service"]
    assert definition.approval_required is True
    assert definition.validate_parameters({}) == []
    assert definition.validate_parameters({"command": "whoami"}) == [
        "this action accepts no parameters"
    ]


def test_demo_plan_is_the_only_plan_with_an_executable_action(client, event_factory) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id="host-demo-plan",
            event_type="demo_service_unhealthy",
            category="operational",
            severity="medium",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert created.status_code == 201, created.text
    plan = client.get(
        f"/api/v1/incidents/{created.json()['incident_id']}/response-plan"
    ).json()
    assert plan["executable_actions"] == ["restart_quietward_demo_service"]
    executable_steps = [
        step
        for step in plan["containment_steps"]
        if step.get("executable_action_type") is not None
    ]
    assert [step["executable_action_type"] for step in executable_steps] == [
        "restart_quietward_demo_service"
    ]


def test_unknown_event_family_stays_advisory(client, event_factory) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id="host-unknown-plan",
            event_type="novel_sensor_signal",
            category="other",
            severity="low",
        ),
    )
    assert created.status_code == 201, created.text
    plan = client.get(
        f"/api/v1/incidents/{created.json()['incident_id']}/response-plan"
    ).json()
    assert plan["attack_families"] == ["unknown"]
    assert plan["executable_actions"] == []
    assert any("cannot be mapped" in item for item in plan["escalation_conditions"])
