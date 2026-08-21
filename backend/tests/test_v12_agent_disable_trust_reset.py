from __future__ import annotations

import json
import secrets
import time

from app.database.models import AgentRecord
from app.services.agent_auth import sign_request


def _signed_post(client, enrollment: dict, target: str, payload: dict, *, key_id: str | None = None, secret: str | None = None):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    resolved_key_id = key_id or enrollment["key_id"]
    resolved_secret = secret or enrollment["secret"]
    signature = sign_request(
        resolved_secret,
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
            "X-QWR-Key-ID": resolved_key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        },
    )


def _capabilities() -> dict:
    return {
        "schema_version": "1.0",
        "agent_version": "1.2.0-alpha.1",
        "supported_actions": ["collect_host_diagnostic"],
        "enabled_actions": ["collect_host_diagnostic"],
        "resource_handle_protocol": "qwrh1",
        "arbitrary_command_execution": False,
    }


def test_disable_clears_capability_trust_and_pending_rotation(client) -> None:
    enrolled = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": "host-disable-reset",
            "display_name": "disable reset agent",
            "agent_version": "1.2.0-alpha.1",
        },
    )
    assert enrolled.status_code == 201, enrolled.text
    enrollment = enrolled.json()

    capability_target = f"/api/v1/agents/{enrollment['agent_id']}/capabilities"
    assert _signed_post(client, enrollment, capability_target, _capabilities()).status_code == 200

    rotate_target = f"/api/v1/agents/{enrollment['agent_id']}/rotate-key"
    prepared = _signed_post(client, enrollment, rotate_target, {})
    assert prepared.status_code == 200, prepared.text
    pending = prepared.json()

    disabled = client.patch(
        f"/api/v1/agents/{enrollment['agent_id']}",
        headers={"X-Actor-ID": "disable-admin"},
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text
    disabled_row = disabled.json()
    assert disabled_row["enabled"] is False
    assert disabled_row["supported_actions"] == []
    assert disabled_row["enabled_actions"] == []
    assert disabled_row["capabilities_updated_at"] is None

    with client.app.state.database.session_factory() as session:
        stored = session.get(AgentRecord, enrollment["agent_id"])
        assert stored is not None
        assert stored.pending_key_id is None
        assert stored.pending_hmac_key_b64 is None
        assert stored.pending_key_expires_at is None

    reenabled = client.patch(
        f"/api/v1/agents/{enrollment['agent_id']}",
        headers={"X-Actor-ID": "disable-admin"},
        json={"enabled": True},
    )
    assert reenabled.status_code == 200, reenabled.text
    reenabled_row = reenabled.json()
    assert reenabled_row["enabled"] is True
    assert reenabled_row["enabled_actions"] == []
    assert reenabled_row["capabilities_updated_at"] is None

    # The staged replacement was explicitly revoked by the analyst disable and
    # therefore cannot activate after re-enable.
    activate_target = f"/api/v1/agents/{enrollment['agent_id']}/activate-key"
    activation = _signed_post(
        client,
        enrollment,
        activate_target,
        {},
        key_id=pending["pending_key_id"],
        secret=pending["secret"],
    )
    assert activation.status_code == 401
    assert activation.json()["detail"]["code"] == "invalid_pending_key"

    # Current credential may establish trust again only by a fresh signed report.
    refreshed = _signed_post(client, enrollment, capability_target, _capabilities())
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["enabled_actions"] == ["collect_host_diagnostic"]
    assert refreshed.json()["capabilities_updated_at"] is not None
