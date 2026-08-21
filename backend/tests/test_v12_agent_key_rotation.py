from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.database.models import AgentRecord
from app.services.agent_auth import sign_request


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"rotation-{host_id}",
            "agent_version": "1.2.0-alpha.1",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_post(client, *, agent_id: str, key_id: str, secret: str, target: str, payload: dict):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    signature = sign_request(
        secret,
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
            "X-QWR-Agent-ID": agent_id,
            "X-QWR-Key-ID": key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        },
    )


def _capability_payload() -> dict:
    return {
        "schema_version": "1.0",
        "agent_version": "1.2.0-alpha.1",
        "supported_actions": [
            "restart_quietward_demo_service",
            "collect_host_diagnostic",
            "collect_process_diagnostic",
            "collect_file_diagnostic",
        ],
        "enabled_actions": [
            "restart_quietward_demo_service",
            "collect_host_diagnostic",
            "collect_process_diagnostic",
            "collect_file_diagnostic",
        ],
        "resource_handle_protocol": "qwrh1",
        "arbitrary_command_execution": False,
    }


def test_rotation_returns_one_time_new_credential_and_both_keys_work_during_grace(client) -> None:
    enrolled = _enroll(client, "host-key-rotation")
    target = f"/api/v1/agents/{enrolled['agent_id']}/rotate-key"
    rotated = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=target,
        payload={},
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.headers["cache-control"].startswith("no-store")
    assert rotated.headers["pragma"] == "no-cache"
    value = rotated.json()
    assert value["agent_id"] == enrolled["agent_id"]
    assert value["key_id"] != enrolled["key_id"]
    assert value["secret"] != enrolled["secret"]

    capability_target = f"/api/v1/agents/{enrolled['agent_id']}/capabilities"
    old_key = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert old_key.status_code == 200, old_key.text

    new_key = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=value["key_id"],
        secret=value["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert new_key.status_code == 200, new_key.text

    listed = client.get("/api/v1/agents").json()
    row = next(item for item in listed if item["agent_id"] == enrolled["agent_id"])
    assert row["key_id"] == value["key_id"]
    assert "secret" not in row
    assert "previous_key_id" not in row


def test_previous_key_is_rejected_after_grace_expires(client) -> None:
    enrolled = _enroll(client, "host-key-expiry")
    rotate_target = f"/api/v1/agents/{enrolled['agent_id']}/rotate-key"
    rotated = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=rotate_target,
        payload={},
    )
    assert rotated.status_code == 200, rotated.text

    with client.app.state.database.session_factory() as session:
        agent = session.get(AgentRecord, enrolled["agent_id"])
        assert agent is not None
        agent.previous_key_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()

    response = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/capabilities",
        payload=_capability_payload(),
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_key_id"


def test_disabled_agent_cannot_rotate_key(client) -> None:
    enrolled = _enroll(client, "host-key-disabled")
    disabled = client.patch(
        f"/api/v1/agents/{enrolled['agent_id']}",
        headers={"X-Actor-ID": "rotation-admin"},
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text

    response = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/rotate-key",
        payload={},
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unknown_or_disabled_agent"


def test_rotation_helper_never_prints_secret_source_contract() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "scripts" / "rotate_response_agent_key.py").read_text(encoding="utf-8")
    assert "The new agent secret was not printed." in text
    assert "print(value[\"secret\"]" not in text
    assert "print(rotated.secret" not in text
