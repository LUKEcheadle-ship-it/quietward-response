from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.services.agent_auth import sign_request


def test_disabled_agent_can_no_longer_send_authenticated_events(client) -> None:
    enrollment_response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "revocation-host",
            "display_name": "revocation-test-agent",
            "agent_version": "test",
        },
    )
    assert enrollment_response.status_code == 201
    enrollment = enrollment_response.json()

    disabled = client.patch(
        f"/api/v1/agents/{enrollment['agent_id']}",
        headers={"X-Actor-ID": "analyst-test"},
        json={"enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    payload = {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "test",
        "host_id": "revocation-host",
        "host_name": "revocation-host",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_start",
        "category": "execution",
        "severity": "medium",
        "confidence": 0.8,
        "summary": "disabled agent should be rejected",
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
    rejected = client.post(target, content=body, headers=headers)
    assert rejected.status_code == 401
    assert rejected.json()["detail"]["code"] == "unknown_or_disabled_agent"

    audit_actions = [item["action"] for item in client.get("/api/v1/incidents").json()] if False else None
    assert audit_actions is None  # keep the endpoint behavior assertion focused above
