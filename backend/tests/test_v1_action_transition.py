from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.services.agent_auth import sign_request


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={"host_id": host_id, "display_name": "transition-agent", "agent_version": "test"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _headers(enrollment: dict, *, method: str, target: str, body: bytes = b"") -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method=method,
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }


def _post_signed(client, enrollment: dict, target: str, payload: dict):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return client.post(
        target,
        content=body,
        headers=_headers(enrollment, method="POST", target=target, body=body),
    )


def test_terminal_result_cannot_skip_executing_state(client, event_factory) -> None:
    host_id = "transition-host"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert event.status_code == 201, event.text
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id)

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action_id = created.json()["action_id"]
    assert client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": "transition test"},
    ).status_code == 200

    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    pending = client.get(
        pending_target,
        headers=_headers(enrollment, method="GET", target=pending_target),
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()[0]["status"] == "dispatching"

    target = f"/api/v1/actions/{action_id}/result"
    direct_terminal = {
        "schema_version": "1.0",
        "action_id": action_id,
        "agent_id": enrollment["agent_id"],
        "host_id": host_id,
        "status": "succeeded",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "result": {"after": "running"},
        "error": None,
        "evidence": {"executor": "test"},
        "agent_version": "test",
    }
    rejected = _post_signed(client, enrollment, target, direct_terminal)
    assert rejected.status_code == 409, rejected.text
    assert rejected.json()["detail"]["code"] == "action_requires_executing_state"

    stored = client.get(f"/api/v1/incidents/{incident_id}/actions").json()[0]
    assert stored["status"] == "dispatching"
    assert stored["result"] is None
