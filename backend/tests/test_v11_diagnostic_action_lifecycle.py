from __future__ import annotations


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"alpha-test-{host_id}",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_file_diagnostic_is_registered_but_raw_path_containment_is_impossible(
    client,
    event_factory,
) -> None:
    host_id = "host-file-response"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="malware_signature",
            category="malware",
            severity="high",
            summary="Synthetic malware evidence",
        ),
    )
    assert event.status_code == 201, event.text
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id)

    plan = client.get(f"/api/v1/incidents/{incident_id}/response-plan")
    assert plan.status_code == 200, plan.text
    assert "malware" in plan.json()["attack_families"]
    assert "collect_file_diagnostic" in plan.json()["executable_actions"]
    assert "quarantine_artifact_by_handle" in plan.json()["executable_actions"]

    diagnostic = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_file_diagnostic",
            "parameters": {},
        },
    )
    assert diagnostic.status_code == 201, diagnostic.text
    assert diagnostic.json()["status"] == "pending"

    raw_path = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "quarantine_artifact_by_handle",
            "parameters": {"path": "/tmp/suspicious"},
        },
    )
    assert raw_path.status_code == 409
    assert "exactly one resource_handle" in raw_path.text

    command_shape = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "run_shell",
            "parameters": {"command": "whoami"},
        },
    )
    assert command_shape.status_code == 409
    assert "unsupported action type" in command_shape.text


def test_process_termination_requires_opaque_handle_not_pid(client, event_factory) -> None:
    host_id = "host-process-response"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="privilege_escalation",
            category="privilege",
            severity="high",
            metadata={"operating_system": "Linux"},
        ),
    )
    assert event.status_code == 201, event.text
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id)

    rejected = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "terminate_process_by_handle",
            "parameters": {"pid": 1234},
        },
    )
    assert rejected.status_code == 409
    assert "exactly one resource_handle" in rejected.text

    accepted_shape = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "terminate_process_by_handle",
            "parameters": {"resource_handle": "qwrh1_1234567890abcdef"},
        },
    )
    assert accepted_shape.status_code == 201, accepted_shape.text
    assert accepted_shape.json()["status"] == "pending"


def test_demo_action_remains_separate_from_real_containment(
    client,
    event_factory,
) -> None:
    host_id = "host-demo-action"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="demo_service_unhealthy",
            category="operational",
            severity="medium",
            summary="Dedicated demo fixture unhealthy",
        ),
    )
    assert event.status_code == 201, event.text
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id)

    plan = client.get(f"/api/v1/incidents/{incident_id}/response-plan").json()
    assert plan["executable_actions"] == ["restart_quietward_demo_service"]

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "pending"
