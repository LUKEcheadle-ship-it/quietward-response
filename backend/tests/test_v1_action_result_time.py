from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.schemas.action import ActionResultCreate
from app.services.agent_auth import sign_request


def test_action_result_schema_rejects_invalid_lifecycle_timestamps() -> None:
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError, match="executing result cannot include completed_at"):
        ActionResultCreate(
            action_id=str(uuid4()),
            agent_id="agent",
            host_id="host",
            status="executing",
            started_at=now,
            completed_at=now,
        )

    with pytest.raises(ValidationError, match="completed_at cannot be earlier"):
        ActionResultCreate(
            action_id=str(uuid4()),
            agent_id="agent",
            host_id="host",
            status="succeeded",
            started_at=now,
            completed_at=now - timedelta(seconds=1),
        )


def test_authenticated_action_result_cannot_claim_far_future_time(client, event_factory) -> None:
    host_id = "result-clock-host"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert event.status_code == 201
    incident_id = event.json()["incident_id"]

    enrollment_response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "result-clock-agent",
            "agent_version": "test",
        },
    )
    assert enrollment_response.status_code == 201
    enrollment = enrollment_response.json()

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201
    action = created.json()
    approved = client.post(
        f"/api/v1/actions/{action['action_id']}/approve",
        json={"reason": "clock validation"},
    )
    assert approved.status_code == 200

    pending_target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    pending_headers = {
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method="GET",
            target=pending_target,
            timestamp=timestamp,
            nonce=nonce,
            body=b"",
        ),
    }
    pending = client.get(pending_target, headers=pending_headers)
    assert pending.status_code == 200
    assert pending.json()[0]["status"] == "dispatching"

    future = datetime.now(timezone.utc) + timedelta(hours=1)
    payload = {
        "schema_version": "1.0",
        "action_id": action["action_id"],
        "agent_id": enrollment["agent_id"],
        "host_id": host_id,
        "status": "succeeded",
        "started_at": future.isoformat(),
        "completed_at": (future + timedelta(seconds=1)).isoformat(),
        "result": {},
        "error": None,
        "evidence": {"executor": "test"},
        "agent_version": "test",
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    target = f"/api/v1/actions/{action['action_id']}/result"
    timestamp = str(int(time.time()))
    nonce = "nonce-" + uuid4().hex
    headers = {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method="POST",
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }
    rejected = client.post(target, content=body, headers=headers)
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "action_result_timestamp_too_far_in_future"
