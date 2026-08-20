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


def test_advisory_file_plan_cannot_be_submitted_as_endpoint_action(
    client,
    event_factory,
) -> None:
    host_id = "host-advisory-file"
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
    assert plan.json()["executable_actions"] == []
    assert any(
        step["step_id"] == "quarantine-artifact" and step["state"] == "planned"
        for step in plan.json()["containment_steps"]
    )

    rejected = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-alpha-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_file_diagnostic",
            "parameters": {},
        },
    )
    assert rejected.status_code == 409
    assert "unsupported action type" in rejected.text

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


def test_demo_action_remains_separate_from_advisory_response_plans(
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
