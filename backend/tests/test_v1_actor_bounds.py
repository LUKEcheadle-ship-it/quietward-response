from __future__ import annotations


def test_action_actor_headers_are_bounded(client, event_factory) -> None:
    event = client.post(
        "/api/v1/events",
        json=event_factory(host_id="actor-bound-host"),
    )
    assert event.status_code == 201
    incident_id = event.json()["incident_id"]

    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "actor-bound-host",
            "display_name": "actor-bound-agent",
            "agent_version": "test",
        },
    )
    assert enrollment.status_code == 201
    agent = enrollment.json()

    oversized = "analyst-" + ("x" * 400)
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": oversized},
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": "actor-bound-host",
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()
    assert len(action["requested_by"]) == 128

    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        headers={"X-Actor-ID": oversized},
        json={"reason": "bounded identity test"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
