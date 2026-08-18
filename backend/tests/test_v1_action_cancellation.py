from __future__ import annotations

import time
from uuid import uuid4

from app.services.agent_auth import sign_request


def _demo_incident(client, event_factory, host_id: str) -> str:
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


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"agent-{host_id}",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _prepare_action(client, incident_id: str, agent: dict, host_id: str) -> dict:
    response = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _poll(client, agent: dict):
    target = f"/api/v1/agents/{agent['agent_id']}/actions/pending"
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    headers = {
        "X-QWR-Agent-ID": agent["agent_id"],
        "X-QWR-Key-ID": agent["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            agent["secret"],
            method="GET",
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=b"",
        ),
    }
    return client.get(target, headers=headers)


def _approve_and_dispatch(client, action: dict, agent: dict) -> None:
    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "pre-execution revocation test"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    polled = _poll(client, agent)
    assert polled.status_code == 200, polled.text
    assert len(polled.json()) == 1
    assert polled.json()[0]["status"] == "dispatching"


def test_closing_incident_cancels_pending_action_and_old_approval_cannot_revive(
    client,
    event_factory,
) -> None:
    host_id = "close-cancel-host"
    incident_id = _demo_incident(client, event_factory, host_id)
    agent = _enroll(client, host_id)
    action = _prepare_action(client, incident_id, agent, host_id)
    assert action["status"] == "pending"

    closed = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
    )
    assert closed.status_code == 200

    stored = client.get(f"/api/v1/incidents/{incident_id}/actions").json()[0]
    assert stored["status"] == "cancelled"
    assert stored["policy_allowed"] is False

    reopened = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
    )
    assert reopened.status_code == 200
    stale_approval = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "must not revive cancelled action"},
    )
    assert stale_approval.status_code == 409


def test_disabling_agent_cancels_approved_undispatched_action(
    client,
    event_factory,
) -> None:
    host_id = "disable-cancel-host"
    incident_id = _demo_incident(client, event_factory, host_id)
    agent = _enroll(client, host_id)
    action = _prepare_action(client, incident_id, agent, host_id)

    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "approved before revocation"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"

    disabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    stored = client.get(f"/api/v1/incidents/{incident_id}/actions").json()[0]
    assert stored["status"] == "cancelled"
    assert stored["policy_allowed"] is False
    assert "target agent is disabled" in stored["policy_reasons"]

    reenabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": True},
    )
    assert reenabled.status_code == 200
    assert reenabled.json()["enabled"] is True
    stale_approval = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "must not revive cancelled action"},
    )
    assert stale_approval.status_code == 409


def test_closing_incident_revokes_dispatching_action_before_execution_ack(
    client,
    event_factory,
) -> None:
    host_id = "close-dispatch-host"
    incident_id = _demo_incident(client, event_factory, host_id)
    agent = _enroll(client, host_id)
    action = _prepare_action(client, incident_id, agent, host_id)
    _approve_and_dispatch(client, action, agent)

    closed = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "resolved"},
    )
    assert closed.status_code == 200, closed.text

    stored = client.get(f"/api/v1/incidents/{incident_id}/actions").json()[0]
    assert stored["status"] == "cancelled"
    assert stored["policy_allowed"] is False
    assert "incident moved to resolved" in stored["policy_reasons"]

    reopened = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating"},
    )
    assert reopened.status_code == 200
    assert _poll(client, agent).json() == []


def test_disabling_agent_revokes_dispatching_action_before_execution_ack(
    client,
    event_factory,
) -> None:
    host_id = "disable-dispatch-host"
    incident_id = _demo_incident(client, event_factory, host_id)
    agent = _enroll(client, host_id)
    action = _prepare_action(client, incident_id, agent, host_id)
    _approve_and_dispatch(client, action, agent)

    disabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text

    stored = client.get(f"/api/v1/incidents/{incident_id}/actions").json()[0]
    assert stored["status"] == "cancelled"
    assert stored["policy_allowed"] is False
    assert "target agent is disabled" in stored["policy_reasons"]

    reenabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": True},
    )
    assert reenabled.status_code == 200
    assert _poll(client, agent).json() == []
