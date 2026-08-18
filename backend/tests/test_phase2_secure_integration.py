from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select

from app.database.models import ActionRecord, ApprovalRecord, AuditRecord
from app.services.agent_auth import sign_request


def _enroll(client, *, host_id: str = "host-alpha") -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"QuietWard on {host_id}",
            "agent_version": "0.4.0a2",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_headers(
    enrollment: dict,
    *,
    method: str,
    target: str,
    body: bytes = b"",
    nonce: str | None = None,
    timestamp: str | None = None,
) -> dict[str, str]:
    resolved_nonce = nonce or ("nonce-" + uuid4().hex)
    resolved_timestamp = timestamp or str(int(time.time()))
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": resolved_timestamp,
        "X-QWR-Nonce": resolved_nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method=method,
            target=target,
            timestamp=resolved_timestamp,
            nonce=resolved_nonce,
            body=body,
        ),
    }


def _quietward_event(host_id: str = "host-alpha", *, event_type: str = "process_start") -> dict:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "0.4.0a2",
        "host_id": host_id,
        "host_name": host_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "category": "execution",
        "severity": "medium",
        "confidence": 0.85,
        "summary": "Authenticated QuietWard test event",
        "evidence": {"synthetic": True},
        "metadata": {"operating_system": "Linux"},
    }


def _post_signed_json(client, enrollment: dict, target: str, payload: dict, *, nonce: str | None = None):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = _signed_headers(
        enrollment,
        method="POST",
        target=target,
        body=body,
        nonce=nonce,
    )
    return client.post(target, content=body, headers=headers)


def _create_approved_action(client, event_factory, enrollment: dict) -> tuple[str, dict]:
    event = client.post("/api/v1/events", json=event_factory(host_id=enrollment["host_id"]))
    assert event.status_code == 201
    incident_id = event.json()["incident_id"]
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": enrollment["host_id"],
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()
    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "test"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    return incident_id, action


def test_enrollment_requires_token(client) -> None:
    rejected = client.post(
        "/api/v1/agents/enroll",
        json={"host_id": "host-a", "display_name": "test"},
    )
    assert rejected.status_code == 401

    enrolled = _enroll(client, host_id="host-a")
    assert enrolled["agent_id"]
    assert enrolled["key_id"]
    assert enrolled["secret"]
    listing = client.get("/api/v1/agents")
    assert listing.status_code == 200
    assert listing.json()[0]["host_id"] == "host-a"
    assert "secret" not in listing.json()[0]


def test_signed_quietward_event_and_tamper_rejection(client) -> None:
    enrollment = _enroll(client)
    payload = _quietward_event()
    accepted = _post_signed_json(client, enrollment, "/api/v1/events", payload)
    assert accepted.status_code == 201, accepted.text

    original_body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    headers = _signed_headers(
        enrollment,
        method="POST",
        target="/api/v1/events",
        body=original_body,
    )
    tampered = dict(payload)
    tampered["event_id"] = str(uuid4())
    tampered_body = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()
    rejected = client.post("/api/v1/events", content=tampered_body, headers=headers)
    assert rejected.status_code == 401
    assert rejected.json()["detail"]["code"] == "invalid_signature"


def test_replay_nonce_and_stale_timestamp_rejected(client) -> None:
    enrollment = _enroll(client)
    payload = _quietward_event()
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    nonce = "nonce-" + uuid4().hex
    headers = _signed_headers(
        enrollment,
        method="POST",
        target="/api/v1/events",
        body=body,
        nonce=nonce,
    )
    first = client.post("/api/v1/events", content=body, headers=headers)
    assert first.status_code == 201

    replay = client.post("/api/v1/events", content=body, headers=headers)
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "replayed_nonce"

    stale_payload = _quietward_event()
    stale_body = json.dumps(stale_payload, sort_keys=True, separators=(",", ":")).encode()
    stale_time = str(int(time.time()) - 1000)
    stale_headers = _signed_headers(
        enrollment,
        method="POST",
        target="/api/v1/events",
        body=stale_body,
        timestamp=stale_time,
    )
    stale = client.post("/api/v1/events", content=stale_body, headers=stale_headers)
    assert stale.status_code == 401
    assert stale.json()["detail"]["code"] == "stale_request"


def test_unsigned_quietward_event_rejected_but_sensor_neutral_demo_remains_compatible(client, event_factory) -> None:
    quietward = client.post("/api/v1/events", json=_quietward_event())
    assert quietward.status_code == 401

    phase1_compatible = client.post("/api/v1/events", json=event_factory())
    assert phase1_compatible.status_code == 201


def test_action_requires_registry_approval_policy_and_correct_agent(client, event_factory) -> None:
    event = client.post("/api/v1/events", json=event_factory(host_id="host-alpha"))
    assert event.status_code == 201
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id="host-alpha")

    unsupported = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": "host-alpha",
            "action_type": "run_shell",
            "parameters": {"command": "whoami"},
        },
    )
    assert unsupported.status_code == 409

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": "host-alpha",
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action = created.json()
    assert action["status"] == "pending"

    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    unsigned = client.get(pending_target)
    assert unsigned.status_code == 401

    headers = _signed_headers(enrollment, method="GET", target=pending_target)
    before_approval = client.get(pending_target, headers=headers)
    assert before_approval.status_code == 200
    assert before_approval.json() == []

    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        headers={"X-Actor-ID": "analyst-test"},
        json={"reason": "controlled Phase 2 test"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["policy_allowed"] is True

    headers = _signed_headers(enrollment, method="GET", target=pending_target)
    delivered = client.get(pending_target, headers=headers)
    assert delivered.status_code == 200
    assert len(delivered.json()) == 1
    assert delivered.json()[0]["action_type"] == "restart_quietward_demo_service"
    assert delivered.json()[0]["status"] == "dispatching"


def test_executing_action_is_redelivered_to_same_agent_for_recovery(client, event_factory) -> None:
    enrollment = _enroll(client, host_id="host-alpha")
    _, action = _create_approved_action(client, event_factory, enrollment)
    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    first_poll = client.get(
        pending_target,
        headers=_signed_headers(enrollment, method="GET", target=pending_target),
    )
    assert first_poll.status_code == 200
    assert first_poll.json()[0]["status"] == "dispatching"

    executing_payload = {
        "schema_version": "1.0",
        "action_id": action["action_id"],
        "agent_id": enrollment["agent_id"],
        "host_id": "host-alpha",
        "status": "executing",
        "result": {},
        "evidence": {"executor": "quietward-demo-fixture-v1"},
        "agent_version": "0.4.0a2",
    }
    executing = _post_signed_json(
        client,
        enrollment,
        f"/api/v1/actions/{action['action_id']}/result",
        executing_payload,
    )
    assert executing.status_code == 200
    assert executing.json()["status"] == "executing"

    recovery_poll = client.get(
        pending_target,
        headers=_signed_headers(enrollment, method="GET", target=pending_target),
    )
    assert recovery_poll.status_code == 200
    assert len(recovery_poll.json()) == 1
    assert recovery_poll.json()[0]["action_id"] == action["action_id"]
    assert recovery_poll.json()[0]["status"] == "executing"


def test_expired_approval_is_persisted_as_expired(client, event_factory) -> None:
    enrollment = _enroll(client, host_id="host-alpha")
    event = client.post("/api/v1/events", json=event_factory(host_id="host-alpha"))
    incident_id = event.json()["incident_id"]
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": "host-alpha",
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    ).json()

    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, created["action_id"])
        assert action is not None and action.approval_id is not None
        approval = session.get(ApprovalRecord, action.approval_id)
        assert approval is not None
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        approval.expires_at = past
        action.expires_at = past
        session.commit()

    expired = client.post(
        f"/api/v1/actions/{created['action_id']}/approve",
        json={"reason": "too late"},
    )
    assert expired.status_code == 200
    assert expired.json()["status"] == "expired"
    assert expired.json()["policy_allowed"] is False
    assert "approval has expired" in expired.json()["policy_reasons"]

    with client.app.state.database.session_factory() as session:
        stored = session.get(ActionRecord, created["action_id"])
        assert stored is not None
        assert stored.status == "expired"


def test_action_result_lifecycle_and_duplicate_terminal_result(client, event_factory) -> None:
    event = client.post("/api/v1/events", json=event_factory(host_id="host-alpha"))
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id="host-alpha")
    other = _enroll(client, host_id="host-other")

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": "host-alpha",
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    ).json()
    client.post(
        f"/api/v1/actions/{created['action_id']}/approve",
        json={"reason": "test"},
    )
    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    client.get(
        pending_target,
        headers=_signed_headers(enrollment, method="GET", target=pending_target),
    )

    wrong_payload = {
        "schema_version": "1.0",
        "action_id": created["action_id"],
        "agent_id": other["agent_id"],
        "host_id": "host-other",
        "status": "succeeded",
        "result": {},
        "evidence": {},
        "agent_version": "0.4.0a2",
    }
    wrong = _post_signed_json(
        client,
        other,
        f"/api/v1/actions/{created['action_id']}/result",
        wrong_payload,
    )
    assert wrong.status_code == 409

    executing_payload = {
        "schema_version": "1.0",
        "action_id": created["action_id"],
        "agent_id": enrollment["agent_id"],
        "host_id": "host-alpha",
        "status": "executing",
        "result": {},
        "evidence": {"executor": "demo"},
        "agent_version": "0.4.0a2",
    }
    executing = _post_signed_json(
        client,
        enrollment,
        f"/api/v1/actions/{created['action_id']}/result",
        executing_payload,
    )
    assert executing.status_code == 200
    assert executing.json()["status"] == "executing"

    final_payload = dict(executing_payload)
    final_payload["status"] = "succeeded"
    final_payload["completed_at"] = datetime.now(timezone.utc).isoformat()
    final_payload["result"] = {"before": "unhealthy", "after": "running"}
    final = _post_signed_json(
        client,
        enrollment,
        f"/api/v1/actions/{created['action_id']}/result",
        final_payload,
    )
    assert final.status_code == 200
    assert final.json()["status"] == "succeeded"

    duplicate = _post_signed_json(
        client,
        enrollment,
        f"/api/v1/actions/{created['action_id']}/result",
        final_payload,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["status"] == "succeeded"

    conflicting = dict(final_payload)
    conflicting["result"] = {"before": "different", "after": "different"}
    rejected = _post_signed_json(
        client,
        enrollment,
        f"/api/v1/actions/{created['action_id']}/result",
        conflicting,
    )
    assert rejected.status_code == 409


def test_audit_chain_verifies_and_detects_tampering(client, event_factory) -> None:
    for index in range(3):
        response = client.post("/api/v1/events", json=event_factory(index=index))
        assert response.status_code == 201
    valid = client.get("/api/v1/audit/verify")
    assert valid.status_code == 200
    assert valid.json()["valid"] is True
    assert valid.json()["entries_checked"] > 0

    with client.app.state.database.session_factory() as session:
        rows = list(session.scalars(select(AuditRecord).order_by(AuditRecord.timestamp.asc(), AuditRecord.audit_id.asc())))
        assert len(rows) > 1
        for previous, current in zip(rows, rows[1:]):
            previous_time = previous.timestamp
            current_time = current.timestamp
            if previous_time.tzinfo is None:
                previous_time = previous_time.replace(tzinfo=timezone.utc)
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)
            assert current_time > previous_time

        first = rows[0]
        first.details = {"tampered": True}
        session.commit()

    invalid = client.get("/api/v1/audit/verify")
    assert invalid.status_code == 200
    assert invalid.json()["valid"] is False
    assert any(item["error"] == "entry_hash_mismatch" for item in invalid.json()["errors"])
