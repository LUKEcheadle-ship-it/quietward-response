from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.services.agent_auth import sign_request


def test_authenticated_nonce_is_consumed_even_when_business_validation_rejects(client) -> None:
    enrollment_response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "host-alpha",
            "display_name": "transaction-test-agent",
            "agent_version": "test",
        },
    )
    assert enrollment_response.status_code == 201
    enrollment = enrollment_response.json()

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

    first = client.post(target, content=body, headers=headers)
    assert first.status_code == 403
    assert first.json()["detail"]["code"] == "agent_host_mismatch"

    replay = client.post(target, content=body, headers=headers)
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "replayed_nonce"
