from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.services.agent_auth import sign_request


def _signed_headers(agent: dict, *, method: str, target: str, body: bytes = b"") -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": agent["agent_id"],
        "X-QWR-Key-ID": agent["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            agent["secret"],
            method=method,
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }


def _post_signed_json(client, agent: dict, target: str, payload: dict):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return client.post(
        target,
        content=body,
        headers=_signed_headers(agent, method="POST", target=target, body=body),
    )


def test_disabled_agent_can_finish_only_already_executing_action(client, event_factory) -> None:
    host_id = "disabled-result-reconciliation-host"
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
    incident_id = incident.json()["incident_id"]

    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "disabled-result-agent",
            "agent_version": "test",
        },
    )
    assert enrollment.status_code == 201, enrollment.text
    agent = enrollment.json()

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()

    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "result reconciliation test"},
    )
    assert approved.status_code == 200, approved.text

    pending_target = f"/api/v1/agents/{agent['agent_id']}/actions/pending"
    polled = client.get(
        pending_target,
        headers=_signed_headers(agent, method="GET", target=pending_target),
    )
    assert polled.status_code == 200, polled.text
    assert polled.json()[0]["status"] == "dispatching"

    started_at = datetime.now(timezone.utc).isoformat()
    result_target = f"/api/v1/actions/{action['action_id']}/result"
    executing_payload = {
        "schema_version": "1.0",
        "action_id": action["action_id"],
        "agent_id": agent["agent_id"],
        "host_id": host_id,
        "status": "executing",
        "started_at": started_at,
        "completed_at": None,
        "result": {},
        "error": None,
        "evidence": {"executor": "quietward-demo-fixture-v1"},
        "agent_version": "test",
    }
    executing = _post_signed_json(client, agent, result_target, executing_payload)
    assert executing.status_code == 200, executing.text
    assert executing.json()["status"] == "executing"

    disabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["enabled"] is False

    # Revocation prevents new polling immediately.
    denied_poll = client.get(
        pending_target,
        headers=_signed_headers(agent, method="GET", target=pending_target),
    )
    assert denied_poll.status_code == 401
    assert denied_poll.json()["detail"]["code"] == "unknown_or_disabled_agent"

    # But the already executing lifecycle can still report its exact terminal result.
    completed_at = datetime.now(timezone.utc).isoformat()
    final_payload = {
        **executing_payload,
        "status": "succeeded",
        "completed_at": completed_at,
        "result": {"before": "unhealthy", "after": "running"},
    }
    final = _post_signed_json(client, agent, result_target, final_payload)
    assert final.status_code == 200, final.text
    assert final.json()["status"] == "succeeded"

    # An identical retry remains idempotent even though the credential is disabled.
    duplicate = _post_signed_json(client, agent, result_target, final_payload)
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["status"] == "succeeded"


def test_disabled_agent_cannot_revive_cancelled_dispatch(client, event_factory) -> None:
    host_id = "disabled-cancelled-result-host"
    incident = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    incident_id = incident.json()["incident_id"]
    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={"host_id": host_id, "display_name": "cancelled-result-agent", "agent_version": "test"},
    )
    agent = enrollment.json()
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    ).json()
    client.post(
        f"/api/v1/actions/{created['action_id']}/approve",
        json={"reason": "cancel before execution"},
    )
    pending_target = f"/api/v1/agents/{agent['agent_id']}/actions/pending"
    assert client.get(
        pending_target,
        headers=_signed_headers(agent, method="GET", target=pending_target),
    ).status_code == 200

    disabled = client.patch(
        f"/api/v1/agents/{agent['agent_id']}",
        json={"enabled": False},
    )
    assert disabled.status_code == 200

    now = datetime.now(timezone.utc).isoformat()
    result_target = f"/api/v1/actions/{created['action_id']}/result"
    executing_payload = {
        "schema_version": "1.0",
        "action_id": created["action_id"],
        "agent_id": agent["agent_id"],
        "host_id": host_id,
        "status": "executing",
        "started_at": now,
        "completed_at": None,
        "result": {},
        "error": None,
        "evidence": {"executor": "quietward-demo-fixture-v1"},
        "agent_version": "test",
    }
    rejected = _post_signed_json(client, agent, result_target, executing_payload)
    assert rejected.status_code == 403
    assert rejected.json()["detail"]["code"] == "disabled_agent_result_not_reconcilable"
