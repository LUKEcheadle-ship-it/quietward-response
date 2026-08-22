from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.database.models import AgentRecord, Base
from app.v13_agent_signature import AgentSignatureError, PublicAgentCredential, key_id_for_public_key
from app.v13_public_credential_model import AgentPublicCredentialRecord
from app.v13_public_credential_service import (
    ACTIVE,
    EXPIRED,
    PENDING,
    REVOKED,
    activate_public_credential_replacement,
    active_public_credential,
    create_initial_public_credential,
    pending_public_credential,
    public_credential_can_verify,
    revoke_active_public_credential,
    stage_public_credential_replacement,
    validate_public_credential_rows,
)


NOW = datetime(2026, 8, 21, 20, 0, tzinfo=timezone.utc)


def _credential(seed: int, agent_id: str = "agent-public-service") -> PublicAgentCredential:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return PublicAgentCredential(
        agent_id=agent_id,
        key_id=key_id_for_public_key(public),
        public_key_b64=base64.urlsafe_b64encode(public).decode("ascii").rstrip("="),
    )


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    session.add(
        AgentRecord(
            agent_id="agent-public-service",
            host_id="host-public-service",
            display_name="v1.3 public credential service test",
            key_id="legacy-hmac-key-id",
            hmac_key_b64="AA==",
            enabled=True,
        )
    )
    session.commit()
    return session


def test_initial_public_credential_is_active_and_public_only() -> None:
    with _session() as session:
        row = create_initial_public_credential(session, _credential(0x10), now=NOW)
        session.commit()
        assert row.status == ACTIVE
        assert row.activated_at == NOW
        assert public_credential_can_verify(row, now=NOW) is True
        assert active_public_credential(session, row.agent_id).key_id == row.key_id
        assert not hasattr(row, "private_key")
        assert not hasattr(row, "hmac_key_b64")


def test_stage_then_activate_replacement_revokes_old_immediately() -> None:
    with _session() as session:
        current = create_initial_public_credential(session, _credential(0x10), now=NOW)
        pending = stage_public_credential_replacement(
            session,
            _credential(0x20),
            expires_at=NOW + timedelta(minutes=5),
            now=NOW + timedelta(seconds=10),
        )
        assert pending.status == PENDING
        assert pending_public_credential(session, current.agent_id, now=NOW + timedelta(seconds=10)).key_id == pending.key_id

        revoked, activated = activate_public_credential_replacement(
            session,
            current.agent_id,
            pending.key_id,
            now=NOW + timedelta(seconds=20),
        )
        session.commit()
        assert revoked.status == REVOKED
        assert revoked.revoked_at == NOW + timedelta(seconds=20)
        assert public_credential_can_verify(revoked, now=NOW + timedelta(seconds=20)) is False
        assert activated.status == ACTIVE
        assert activated.activated_at == NOW + timedelta(seconds=20)
        assert public_credential_can_verify(activated, now=NOW + timedelta(seconds=20)) is True
        assert active_public_credential(session, current.agent_id).key_id == activated.key_id


def test_only_one_pending_replacement_is_allowed() -> None:
    with _session() as session:
        create_initial_public_credential(session, _credential(0x10), now=NOW)
        stage_public_credential_replacement(
            session,
            _credential(0x20),
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
        with pytest.raises(AgentSignatureError, match="already has a pending"):
            stage_public_credential_replacement(
                session,
                _credential(0x30),
                expires_at=NOW + timedelta(minutes=5),
                now=NOW,
            )


def test_expired_pending_replacement_is_marked_expired_and_not_activated() -> None:
    with _session() as session:
        current = create_initial_public_credential(session, _credential(0x10), now=NOW)
        pending = stage_public_credential_replacement(
            session,
            _credential(0x20),
            expires_at=NOW + timedelta(seconds=30),
            now=NOW,
        )
        assert pending_public_credential(
            session,
            current.agent_id,
            now=NOW + timedelta(seconds=31),
        ) is None
        session.flush()
        expired = session.get(AgentPublicCredentialRecord, pending.credential_id)
        assert expired is not None
        assert expired.status == EXPIRED
        with pytest.raises(AgentSignatureError, match="current pending key"):
            activate_public_credential_replacement(
                session,
                current.agent_id,
                pending.key_id,
                now=NOW + timedelta(seconds=31),
            )


def test_revoke_active_also_revokes_any_pending_replacement() -> None:
    with _session() as session:
        current = create_initial_public_credential(session, _credential(0x10), now=NOW)
        pending = stage_public_credential_replacement(
            session,
            _credential(0x20),
            expires_at=NOW + timedelta(minutes=5),
            now=NOW,
        )
        revoke_active_public_credential(session, current.agent_id, now=NOW + timedelta(seconds=5))
        session.commit()
        assert current.status == REVOKED
        assert pending.status == REVOKED
        assert active_public_credential(session, current.agent_id) is None
        assert public_credential_can_verify(current, now=NOW + timedelta(seconds=5)) is False
        assert public_credential_can_verify(pending, now=NOW + timedelta(seconds=5)) is False


def test_cross_agent_or_same_key_replacement_is_rejected() -> None:
    with _session() as session:
        current = create_initial_public_credential(session, _credential(0x10), now=NOW)
        with pytest.raises(AgentSignatureError, match="replacement key must differ"):
            stage_public_credential_replacement(
                session,
                current.credential if hasattr(current, "credential") else _credential(0x10),
                expires_at=NOW + timedelta(minutes=5),
                now=NOW,
            )

        other = _credential(0x20, agent_id="other-agent")
        with pytest.raises(AgentSignatureError):
            stage_public_credential_replacement(
                session,
                other,
                expires_at=NOW + timedelta(minutes=5),
                now=NOW,
            )


def test_row_set_validator_rejects_duplicate_active_or_pending_state() -> None:
    active_one = AgentPublicCredentialRecord(
        agent_id="agent-a",
        key_id="qwrpk1_" + "1" * 32,
        algorithm="Ed25519",
        protocol_version="qwr-agent-signature-v1",
        public_key_b64="A" * 43,
        status=ACTIVE,
        created_at=NOW,
        activated_at=NOW,
    )
    active_two = AgentPublicCredentialRecord(
        agent_id="agent-a",
        key_id="qwrpk1_" + "2" * 32,
        algorithm="Ed25519",
        protocol_version="qwr-agent-signature-v1",
        public_key_b64="B" * 43,
        status=ACTIVE,
        created_at=NOW,
        activated_at=NOW,
    )
    with pytest.raises(AgentSignatureError, match="multiple active"):
        validate_public_credential_rows([active_one, active_two])
