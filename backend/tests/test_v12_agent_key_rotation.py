from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from app.database.models import AgentRecord, AuditRecord
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


def _prepare(client, enrolled: dict):
    return _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/rotate-key",
        payload={},
    )


def _activate(client, enrolled: dict, prepared: dict):
    return _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=prepared["pending_key_id"],
        secret=prepared["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/activate-key",
        payload={},
    )


def test_rotation_requires_pending_key_proof_and_immediately_revokes_old_key(client) -> None:
    enrolled = _enroll(client, "host-key-rotation")
    prepared_response = _prepare(client, enrolled)
    assert prepared_response.status_code == 200, prepared_response.text
    assert prepared_response.headers["cache-control"].startswith("no-store")
    assert prepared_response.headers["pragma"] == "no-cache"
    prepared = prepared_response.json()
    assert prepared["agent_id"] == enrolled["agent_id"]
    assert prepared["pending_key_id"] != enrolled["key_id"]
    assert prepared["secret"] != enrolled["secret"]

    capability_target = f"/api/v1/agents/{enrolled['agent_id']}/capabilities"
    current_still_active = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert current_still_active.status_code == 200, current_still_active.text

    pending_cannot_use_normal_api = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=prepared["pending_key_id"],
        secret=prepared["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert pending_cannot_use_normal_api.status_code == 401
    assert pending_cannot_use_normal_api.json()["detail"]["code"] == "invalid_key_id"

    current_cannot_activate = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/activate-key",
        payload={},
    )
    assert current_cannot_activate.status_code == 401
    assert current_cannot_activate.json()["detail"]["code"] == "invalid_pending_key"

    activated_response = _activate(client, enrolled, prepared)
    assert activated_response.status_code == 200, activated_response.text
    activated = activated_response.json()
    assert activated["key_id"] == prepared["pending_key_id"]
    assert "secret" not in activated
    assert "previous_key_revoked_at" in activated
    assert "previous_key_expires_at" not in activated

    new_key = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=prepared["pending_key_id"],
        secret=prepared["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert new_key.status_code == 200, new_key.text

    old_key = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=capability_target,
        payload=_capability_payload(),
    )
    assert old_key.status_code == 401
    assert old_key.json()["detail"]["code"] == "invalid_key_id"

    previous_cannot_rotate = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/rotate-key",
        payload={},
    )
    assert previous_cannot_rotate.status_code == 401
    assert previous_cannot_rotate.json()["detail"]["code"] == "invalid_key_id"

    listed = client.get("/api/v1/agents").json()
    row = next(item for item in listed if item["agent_id"] == enrolled["agent_id"])
    assert row["key_id"] == prepared["pending_key_id"]
    assert "secret" not in row
    assert "pending_key_id" not in row
    assert "previous_key_id" not in row

    with client.app.state.database.session_factory() as session:
        agent = session.get(AgentRecord, enrolled["agent_id"])
        assert agent is not None
        assert agent.previous_key_id == enrolled["key_id"]
        assert agent.previous_key_revoked_at is not None
        revoked_at = agent.previous_key_revoked_at
        if revoked_at.tzinfo is None:
            revoked_at = revoked_at.replace(tzinfo=timezone.utc)
        assert revoked_at <= datetime.now(timezone.utc)
        # The ORM schema itself must not expose any retired HMAC material field.
        assert not hasattr(agent, "previous_hmac_key_b64")
        assert not hasattr(agent, "previous_key_expires_at")

        rotation_audits = list(
            session.scalars(
                select(AuditRecord).where(
                    AuditRecord.action.in_([
                        "agent_key_rotation_prepared",
                        "agent_key_rotated",
                    ])
                )
            )
        )
        assert len(rotation_audits) == 2
        serialized = json.dumps([item.details for item in rotation_audits], sort_keys=True)
        assert enrolled["secret"] not in serialized
        assert prepared["secret"] not in serialized
        assert "previous_key_revoked_at" in serialized


def test_rotation_preparation_is_single_flight_and_preserves_first_pending_key(client) -> None:
    enrolled = _enroll(client, "host-key-single-flight")
    first_response = _prepare(client, enrolled)
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()

    second = _prepare(client, enrolled)
    assert second.status_code == 409
    detail = second.json()["detail"]
    assert detail["code"] == "pending_key_rotation_exists"
    assert "activate or recover" in detail["message"]
    assert detail["pending_key_expires_at"] == first["pending_key_expires_at"]

    activated = _activate(client, enrolled, first)
    assert activated.status_code == 200, activated.text
    assert activated.json()["key_id"] == first["pending_key_id"]


def test_expired_pending_key_can_be_replaced_by_new_rotation(client) -> None:
    enrolled = _enroll(client, "host-key-reprepare")
    first_response = _prepare(client, enrolled)
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()

    with client.app.state.database.session_factory() as session:
        agent = session.get(AgentRecord, enrolled["agent_id"])
        assert agent is not None
        agent.pending_key_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()

    second_response = _prepare(client, enrolled)
    assert second_response.status_code == 200, second_response.text
    second = second_response.json()
    assert second["pending_key_id"] != first["pending_key_id"]
    assert second["secret"] != first["secret"]

    old_pending = _activate(client, enrolled, first)
    assert old_pending.status_code == 401
    assert old_pending.json()["detail"]["code"] == "invalid_pending_key"
    current_pending = _activate(client, enrolled, second)
    assert current_pending.status_code == 200, current_pending.text


def test_pending_key_expiry_fails_activation_without_replacing_current_key(client) -> None:
    enrolled = _enroll(client, "host-pending-expiry")
    prepared_response = _prepare(client, enrolled)
    assert prepared_response.status_code == 200, prepared_response.text
    prepared = prepared_response.json()

    with client.app.state.database.session_factory() as session:
        agent = session.get(AgentRecord, enrolled["agent_id"])
        assert agent is not None
        agent.pending_key_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()

    activated = _activate(client, enrolled, prepared)
    assert activated.status_code == 401
    assert activated.json()["detail"]["code"] == "invalid_pending_key"

    current_still_works = _signed_post(
        client,
        agent_id=enrolled["agent_id"],
        key_id=enrolled["key_id"],
        secret=enrolled["secret"],
        target=f"/api/v1/agents/{enrolled['agent_id']}/capabilities",
        payload=_capability_payload(),
    )
    assert current_still_works.status_code == 200, current_still_works.text


def test_disabled_agent_cannot_prepare_or_activate_rotation(client) -> None:
    enrolled = _enroll(client, "host-key-disabled")
    prepared_response = _prepare(client, enrolled)
    assert prepared_response.status_code == 200, prepared_response.text
    prepared = prepared_response.json()

    disabled = client.patch(
        f"/api/v1/agents/{enrolled['agent_id']}",
        headers={"X-Actor-ID": "rotation-admin"},
        json={"enabled": False},
    )
    assert disabled.status_code == 200, disabled.text

    new_prepare = _prepare(client, enrolled)
    assert new_prepare.status_code == 401
    assert new_prepare.json()["detail"]["code"] == "unknown_or_disabled_agent"

    activation = _activate(client, enrolled, prepared)
    assert activation.status_code == 401
    assert activation.json()["detail"]["code"] == "unknown_or_disabled_agent"


def test_rotation_helper_stages_recovery_credential_and_never_prints_secret() -> None:
    root = Path(__file__).resolve().parents[2]
    text = (root / "scripts" / "rotate_response_agent_key.py").read_text(encoding="utf-8")
    assert "--recover-next" in text
    assert 'path.name + ".next"' in text
    assert "write_agent_config(next_path, rotated, force=False)" in text
    assert "_activate(rotated_agent)" in text
    assert "sync_capabilities(rotated_agent)" in text
    assert "os.replace(next_path, path)" in text
    assert "The new agent secret was not printed." in text
    assert "print(prepared[\"secret\"]" not in text
    assert "print(rotated.secret" not in text
