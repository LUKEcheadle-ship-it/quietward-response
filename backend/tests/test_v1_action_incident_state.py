from __future__ import annotations

from app.database.models import ActionRecord
from app.services.policy_service import evaluate_action_policy


def _demo_incident(client, event_factory, host_id: str = "incident-state-host") -> str:
    response = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert response.status_code == 201, response.text
    return response.json()["incident_id"]


def _enroll(client, host_id: str = "incident-state-host") -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "incident-state-agent",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _action_payload(agent: dict, host_id: str = "incident-state-host") -> dict:
    return {
        "target_agent_id": agent["agent_id"],
        "target_host_id": host_id,
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
    }


def test_resolved_incident_rejects_new_response_action(client, event_factory) -> None:
    incident_id = _demo_incident(client, event_factory)
    agent = _enroll(client)
    closed = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Actor-ID": "analyst-test"},
        json={"status": "resolved"},
    )
    assert closed.status_code == 200

    rejected = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_action_payload(agent),
    )
    assert rejected.status_code == 409
    assert "enabled recommendation" in rejected.text


def test_policy_blocks_prepared_action_after_incident_is_resolved(
    client,
    event_factory,
) -> None:
    incident_id = _demo_incident(client, event_factory)
    agent = _enroll(client)
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_action_payload(agent),
    )
    assert created.status_code == 201, created.text
    action_id = created.json()["action_id"]
    approved = client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": "approved while incident is open"},
    )
    assert approved.status_code == 200
    assert approved.json()["policy_allowed"] is True

    closed = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
    )
    assert closed.status_code == 200

    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, action_id)
        assert action is not None
        allowed, reasons = evaluate_action_policy(session, action)

    assert allowed is False
    assert "incident status does not allow response actions" in reasons
