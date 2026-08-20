from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.services.agent_auth import sign_request


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "action-time-agent",
            "agent_version": "test",
        },
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


def test_terminal_result_does_not_rewrite_first_execution_start(client, event_factory) -> None:
    host_id = "start-time-host"
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
    approved = client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": "start-time regression"},
    )
    assert approved.status_code == 200, approved.text

    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    pending = client.get(
        pending_target,
        headers=_headers(enrollment, method="GET", target=pending_target),
    )
    assert pending.status_code == 200, pending.text
    assert pending.json()[0]["status"] == "dispatching"

    first_start = datetime.now(timezone.utc) - timedelta(seconds=2)
    executing_payload = {
        "schema_version": "1.0",
        "action_id": action_id,
        "agent_id": enrollment["agent_id"],
        "host_id": host_id,
        "status": "executing",
        "started_at": first_start.isoformat(),
        "completed_at": None,
        "result": {},
        "error": None,
        "evidence": {"executor": "test"},
        "agent_version": "test",
    }
    target = f"/api/v1/actions/{action_id}/result"
    executing = _post_signed(client, enrollment, target, executing_payload)
    assert executing.status_code == 200, executing.text

    later_start = datetime.now(timezone.utc)
    completed_at = later_start + timedelta(milliseconds=10)
    final_payload = {
        **executing_payload,
        "status": "succeeded",
        "started_at": later_start.isoformat(),
        "completed_at": completed_at.isoformat(),
        "result": {"before": "unhealthy", "after": "running"},
    }
    final = _post_signed(client, enrollment, target, final_payload)
    assert final.status_code == 200, final.text
    body = final.json()
    assert body["status"] == "succeeded"
    stored_start = datetime.fromisoformat(body["started_at"].replace("Z", "+00:00"))
    assert abs((stored_start - first_start).total_seconds()) < 0.001
    assert datetime.fromisoformat(body["completed_at"].replace("Z", "+00:00")) >= stored_start
