from __future__ import annotations

import time
from uuid import uuid4

from app.database.models import ActionRecord, ApprovalRecord
from app.services.agent_auth import sign_request


def _signed_headers(agent: dict, target: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    return {
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


def test_dispatch_rejects_approval_cross_link_tampering(client, event_factory) -> None:
    host_id = "approval-binding-host"
    incident = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert incident.status_code == 201
    incident_id = incident.json()["incident_id"]

    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={"host_id": host_id, "display_name": "approval-binding-agent", "agent_version": "test"},
    )
    assert enrollment.status_code == 201
    agent = enrollment.json()

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "requesting-analyst"},
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201
    action_id = created.json()["action_id"]

    approved = client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers={"X-Actor-ID": "approving-analyst"},
        json={"reason": "binding test"},
    )
    assert approved.status_code == 200
    assert approved.json()["policy_allowed"] is True

    # Simulate accidental/corrupt persistence cross-linking after approval. Dispatch
    # policy must re-check redundant lifecycle identity instead of trusting status.
    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, action_id)
        assert action is not None and action.approval_id
        approval = session.get(ApprovalRecord, action.approval_id)
        assert approval is not None
        approval.requested_by = "tampered-requester"
        session.commit()

    target = f"/api/v1/agents/{agent['agent_id']}/actions/pending"
    poll = client.get(target, headers=_signed_headers(agent, target))
    assert poll.status_code == 200, poll.text
    assert poll.json() == []

    actions = client.get(f"/api/v1/incidents/{incident_id}/actions")
    assert actions.status_code == 200
    stored = actions.json()[0]
    assert stored["status"] == "cancelled"
    assert "approval requester does not match action requester" in stored["policy_reasons"]
