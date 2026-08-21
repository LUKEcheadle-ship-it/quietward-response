from __future__ import annotations

import json
import secrets
import time

from app.services.agent_auth import sign_request


def _signed_capability_report(client, enrollment: dict):
    target = f"/api/v1/agents/{enrollment['agent_id']}/capabilities"
    payload = {
        "schema_version": "1.0",
        "agent_version": "1.2.0-alpha.1",
        "supported_actions": ["collect_host_diagnostic"],
        "enabled_actions": ["collect_host_diagnostic"],
        "resource_handle_protocol": "qwrh1",
        "arbitrary_command_execution": False,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signature = sign_request(
        enrollment["secret"],
        method="POST",
        target=target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return client.post(
        target,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-QWR-Agent-ID": enrollment["agent_id"],
            "X-QWR-Key-ID": enrollment["key_id"],
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        },
    )


def test_disabled_agent_cannot_refresh_capability_trust_state(client) -> None:
    enrolled = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "host-disabled-capability",
            "display_name": "disabled capability test",
            "agent_version": "1.2.0-alpha.1",
        },
    )
    assert enrolled.status_code == 201, enrolled.text
    enrollment = enrolled.json()
    assert _signed_capability_report(client, enrollment).status_code == 200

    disabled = client.patch(
        f"/api/v1/agents/{enrollment['agent_id']}",
        headers={"X-Actor-ID": "capability-admin"},
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text

    rejected = _signed_capability_report(client, enrollment)
    assert rejected.status_code == 401
    assert rejected.json()["detail"]["code"] == "unknown_or_disabled_agent"
