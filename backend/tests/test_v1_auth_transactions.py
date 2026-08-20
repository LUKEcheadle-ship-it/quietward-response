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
            "display_name": f"transaction-test-{host_id}",
            "agent_version": "test",
        },
    )
    assert response.status_code == 201
    return response.json()


def _signed_event_headers(enrollment: dict, payload: dict) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    target = "/api/v1/events"
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
    return body, headers


def test_authenticated_nonce_is_consumed_even_when_business_validation_rejects(client) -> None:
    enrollment = _enroll(client, "host-alpha")

    # The agent is valid and the signature is valid, but the event claims another
    # host. Business validation should reject it after authentication succeeds.
    payload = {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "test",
        "host_id": "host-other",
        "host_name": "host-other",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_start",
        "category": "execution",
        "severity": "medium",
        "confidence": 0.8,
        "summary": "host mismatch nonce-consumption test",
        "evidence": {"synthetic": True},
        "metadata": {"operating_system": "Linux"},
    }
    body, headers = _signed_event_headers(enrollment, payload)

    first = client.post("/api/v1/events", content=body, headers=headers)
    assert first.status_code == 403
    assert first.json()["detail"]["code"] == "agent_host_mismatch"

    replay = client.post("/api/v1/events", content=body, headers=headers)
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "replayed_nonce"


def test_authenticated_future_event_is_rejected_without_poisoning_host_time(client) -> None:
    enrollment = _enroll(client, "future-host")
    payload = {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "test",
        "host_id": "future-host",
        "host_name": "future-host",
        "timestamp": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "event_type": "process_start",
        "category": "execution",
        "severity": "medium",
        "confidence": 0.8,
        "summary": "future timestamp must fail",
        "evidence": {"synthetic": True},
        "metadata": {"operating_system": "Linux"},
    }
    body, headers = _signed_event_headers(enrollment, payload)
    rejected = client.post("/api/v1/events", content=body, headers=headers)
    assert rejected.status_code == 422
    assert rejected.json()["detail"]["code"] == "event_timestamp_too_far_in_future"

    # The rejected event must not create a host record whose last-seen timestamp
    # would remain poisoned by the future value.
    host = client.get("/api/v1/hosts/future-host")
    assert host.status_code == 404
