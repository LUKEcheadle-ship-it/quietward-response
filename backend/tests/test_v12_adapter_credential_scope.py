from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone
from uuid import uuid4

from app.services.agent_auth import (
    derive_event_ingestion_subkey_from_secret,
    sign_event_ingestion_request,
)


def _enroll(client, host_id: str = "host-adapter-scope") -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "adapter scope test endpoint",
            "agent_version": "1.2.0-alpha.1",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _subkey_headers(
    enrollment: dict,
    *,
    method: str,
    target: str,
    body: bytes = b"",
    subkey: bytes | None = None,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    key = subkey or derive_event_ingestion_subkey_from_secret(enrollment["secret"])
    signature = sign_event_ingestion_request(
        key,
        method=method,
        target=target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": signature,
    }


def _quietward_event(host_id: str) -> dict:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "quietward-adapter-v1",
        "host_id": host_id,
        "host_name": host_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_start",
        "category": "execution",
        "severity": "high",
        "confidence": 0.95,
        "summary": "event-only credential test",
        "evidence": {
            "quietward_event_id": "fse-scope-test",
            "attributes": {"suspicious_markers": ["reverse_shell"]},
        },
        "process": {
            "image": "powershell.exe",
            "suspicious_markers": ["reverse_shell"],
        },
        "metadata": {"operating_system": "Windows"},
    }


def test_event_subkey_can_ingest_but_cannot_poll_actions(client) -> None:
    enrollment = _enroll(client)
    payload = _quietward_event(enrollment["host_id"])
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    accepted = client.post(
        "/api/v1/events",
        content=body,
        headers=_subkey_headers(
            enrollment,
            method="POST",
            target="/api/v1/events",
            body=body,
        ),
    )
    assert accepted.status_code == 201, accepted.text

    target = f"/api/v1/agents/{enrollment['agent_id']}/actions/pending"
    rejected = client.get(
        target,
        headers=_subkey_headers(enrollment, method="GET", target=target),
    )
    assert rejected.status_code == 401
    assert rejected.json()["detail"]["code"] == "invalid_signature"


def test_endpoint_key_remains_backward_compatible_for_event_ingestion(client) -> None:
    # Existing endpoint integrations may still sign events with the full key. The
    # deployed adapter receives only the subkey, so compatibility does not weaken
    # adapter least privilege.
    from app.services.agent_auth import sign_request

    enrollment = _enroll(client, "host-endpoint-event-compat")
    payload = _quietward_event(enrollment["host_id"])
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    headers = {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method="POST",
            target="/api/v1/events",
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }
    response = client.post("/api/v1/events", content=body, headers=headers)
    assert response.status_code == 201, response.text


def test_event_subkey_changes_when_endpoint_secret_changes() -> None:
    first = derive_event_ingestion_subkey_from_secret("first-endpoint-secret")
    second = derive_event_ingestion_subkey_from_secret("second-endpoint-secret")
    assert len(first) == 32
    assert len(second) == 32
    assert first != second
    # Basic domain-separation sanity: the subkey is not the endpoint HMAC key.
    endpoint = hashlib.sha256(
        ("quietward-response-v1:" + "first-endpoint-secret").encode("utf-8")
    ).digest()
    assert not hmac.compare_digest(first, endpoint)
