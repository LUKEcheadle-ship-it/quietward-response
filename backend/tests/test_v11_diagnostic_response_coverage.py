from __future__ import annotations

import pytest

from app.database.models import IncidentRecord
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

    assert plan["schema_version"] == "1.1"
    assert plan["mode"] == "advisory_with_controlled_actions"
    assert expected_family in plan["attack_families"]
    assert "unknown" not in plan["attack_families"]
    assert plan["investigation_steps"]
    assert plan["containment_steps"] or plan["recovery_steps"]
    assert "collect_host_diagnostic" in plan["executable_actions"]
    assert all(
        step["state"] in {"available", "manual", "planned", "blocked"}
        for section in ("investigation_steps", "containment_steps", "recovery_steps")
        for step in plan[section]
    )

    if expected_family in {"execution", "privilege"}:
        assert "collect_process_diagnostic" in plan["executable_actions"]
        assert "terminate_process_by_handle" in plan["executable_actions"]
    if expected_family == "malware":
        assert "collect_file_diagnostic" in plan["executable_actions"]
        assert "quarantine_artifact_by_handle" in plan["executable_actions"]
        assert "restore_quarantined_artifact_by_handle" in plan["executable_actions"]
    if expected_family == "network":
        assert "collect_network_diagnostic" in plan["executable_actions"]


def test_executable_registry_is_narrow_and_typed() -> None:
    assert set(ACTION_REGISTRY) == {
        "restart_quietward_demo_service",
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "collect_network_diagnostic",
        "terminate_process_by_handle",
        "collect_file_diagnostic",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
    }

    demo = ACTION_REGISTRY["restart_quietward_demo_service"]
    assert demo.validate_parameters({}) == []
    assert demo.validate_parameters({"command": "whoami"}) == [
        "this action accepts no parameters"
    ]

    network = ACTION_REGISTRY["collect_network_diagnostic"]
    assert network.supported_os == ("linux",)
    assert network.risk_level == "low"
    assert network.validate_parameters({}) == []
    assert network.validate_parameters({"remote_address": "203.0.113.5"}) == [
        "this action accepts no parameters"
    ]

    process = ACTION_REGISTRY["terminate_process_by_handle"]
    assert process.validate_parameters({"resource_handle": "qwrh1_1234567890abcdef"}) == []
    assert process.validate_parameters({"pid": 1234}) == [
        "this action requires exactly one resource_handle parameter"
    ]
    assert process.validate_parameters({"resource_handle": "1234"}) == [
        "resource_handle format is invalid"
    ]


def test_demo_plan_stays_separate_from_real_containment(client, event_factory) -> None:
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


def test_unknown_event_family_gets_only_safe_host_diagnostic(client, event_factory) -> None:
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
    assert plan["executable_actions"] == ["collect_host_diagnostic"]
    assert any("cannot be mapped" in item for item in plan["escalation_conditions"])


def test_pre_v12_incident_does_not_gain_new_executable_actions_retroactively(
    client,
    event_factory,
) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id="host-legacy-policy",
            event_type="malware_signature",
            category="malware",
            severity="high",
        ),
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident_id"]

    with client.app.state.database.session_factory() as session:
        incident = session.get(IncidentRecord, incident_id)
        assert incident is not None
        incident.recommended_actions = [
            {
                "action_type": "diagnostic",
                "title": "Legacy advisory",
                "description": "Historical non-executable recommendation",
                "enabled": True,
                "phase": "v1",
                "registry_action_type": None,
                "requires_approval": False,
            }
        ]
        session.commit()

    plan = client.get(f"/api/v1/incidents/{incident_id}/response-plan").json()
    assert plan["attack_families"] == ["malware"]
    assert plan["executable_actions"] == []
    assert all(
        step.get("executable_action_type") is None
        for section in ("investigation_steps", "containment_steps", "recovery_steps")
        for step in plan[section]
    )
