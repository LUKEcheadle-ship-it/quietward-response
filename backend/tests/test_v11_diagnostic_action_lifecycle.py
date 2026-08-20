from __future__ import annotations

import time
from uuid import uuid4

from app.services.agent_auth import sign_request


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"diagnostic-test-{host_id}",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_get_headers(enrollment: dict, target: str) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    return {
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method="GET",
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=b"",
        ),
    }


def test_file_diagnostic_requires_recommendation_approval_and_signed_poll(
    client,
    event_factory,
) -> None:
    host_id = "host-diagnostic"
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

    command_injection = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_file_diagnostic",
            "parameters": {"command": "whoami"},
        },
    )
    assert command_injection.status_code == 409
    assert "accepts no parameters" in command_injection.text

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "analyst-diagnostic-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_file_diagnostic",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()
    assert action["status"] == "pending"

    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    before = client.get(
        pending_target,
        headers=_signed_get_headers(enrollment, pending_target),
    )
    assert before.status_code == 200
    assert before.json() == []

    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        headers={"X-Actor-ID": "analyst-diagnostic-test"},
        json={"reason": "collect bounded evidence"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["policy_allowed"] is True

    delivered = client.get(
        pending_target,
        headers=_signed_get_headers(enrollment, pending_target),
    )
    assert delivered.status_code == 200
    assert len(delivered.json()) == 1
    assert delivered.json()[0]["action_id"] == action["action_id"]
    assert delivered.json()[0]["action_type"] == "collect_file_diagnostic"
    assert delivered.json()[0]["parameters"] == {}
    assert delivered.json()[0]["status"] == "dispatching"
