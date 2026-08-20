from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.database.models import ActionRecord, ApprovalRecord


def _setup(client, event_factory, host_id: str = "expiry-retry-host") -> tuple[str, dict]:
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
            "display_name": "expiry-retry-agent",
            "agent_version": "test",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    return incident.json()["incident_id"], enrollment.json()


def _payload(agent: dict, host_id: str = "expiry-retry-host") -> dict:
    return {
        "target_agent_id": agent["agent_id"],
        "target_host_id": host_id,
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
    }


def test_expired_pending_action_is_reported_expired_and_does_not_wedge_retry(
    client,
    event_factory,
) -> None:
    incident_id, agent = _setup(client, event_factory)
    first = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_payload(agent),
    )
    assert first.status_code == 201, first.text
    first_action = first.json()

    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, first_action["action_id"])
        assert action is not None and action.approval_id is not None
        approval = session.get(ApprovalRecord, action.approval_id)
        assert approval is not None
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        action.expires_at = past
        approval.expires_at = past
        session.commit()

    # Serialization should immediately expose the lifecycle as expired even before
    # a later mutation persists the cleanup transition.
    actions_before_retry = client.get(
        f"/api/v1/incidents/{incident_id}/actions"
    )
    assert actions_before_retry.status_code == 200
    old_view = next(
        item
        for item in actions_before_retry.json()
        if item["action_id"] == first_action["action_id"]
    )
    assert old_view["status"] == "expired"
    assert old_view["policy_allowed"] is False
    assert old_view["policy_reasons"] == ["action request has expired"]

    retry = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json=_payload(agent),
    )
    assert retry.status_code == 201, retry.text
    assert retry.json()["action_id"] != first_action["action_id"]

    # Creating the replacement persists expiry of the stale lifecycle and its
    # approval rather than leaving misleading pending state in storage.
    with client.app.state.database.session_factory() as session:
        old_action = session.get(ActionRecord, first_action["action_id"])
        assert old_action is not None and old_action.approval_id is not None
        old_approval = session.get(ApprovalRecord, old_action.approval_id)
        assert old_approval is not None
        assert old_action.status == "expired"
        assert old_action.policy_allowed is False
        assert old_approval.status == "expired"
