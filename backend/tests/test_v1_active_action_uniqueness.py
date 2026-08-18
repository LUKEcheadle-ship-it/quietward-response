from __future__ import annotations


def _setup(client, event_factory, host_id: str = "active-action-host") -> tuple[str, dict]:
    incident = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert incident.status_code == 201, incident.text
    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "active-action-agent",
            "agent_version": "test",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    return incident.json()["incident_id"], enrollment.json()


def _payload(agent: dict, host_id: str = "active-action-host") -> dict:
    return {
        "target_agent_id": agent["agent_id"],
        "target_host_id": host_id,
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
    }


def test_duplicate_active_action_is_rejected_but_terminal_action_does_not_block_retry(
    client,
    event_factory,
) -> None:
    incident_id, agent = _setup(client, event_factory)
    first = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_payload(agent),
    )
    assert first.status_code == 201, first.text

    duplicate = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_payload(agent),
    )
    assert duplicate.status_code == 409
    assert "active action of this type already exists" in duplicate.text

    rejected = client.post(
        f"/api/v1/actions/{first.json()['action_id']}/reject",
        json={"reason": "test terminal state"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected"

    retry = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_payload(agent),
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["action_id"] != first.json()["action_id"]
