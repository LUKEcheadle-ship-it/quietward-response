from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.v13_agent_signature import AgentSignatureError, PublicAgentCredential, key_id_for_public_key
from app.v13_public_credential_state import (
    activate_replacement,
    credential_can_verify,
    expire_pending,
    new_active_credential,
    new_pending_credential,
)


def _credential(seed_byte: int, agent_id: str = "agent-state-test") -> PublicAgentCredential:
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    encoded = base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")
    return PublicAgentCredential(
        agent_id=agent_id,
        key_id=key_id_for_public_key(public),
        public_key_b64=encoded,
    )


def test_replacement_activation_revokes_old_public_credential_immediately() -> None:
    current = new_active_credential(_credential(0x55), now_epoch=100)
    pending = new_pending_credential(
        _credential(0x66),
        now_epoch=110,
        expires_at_epoch=200,
    )
    revoked, active = activate_replacement(current, pending, now_epoch=120)
    assert revoked.status == "revoked"
    assert revoked.revoked_at_epoch == 120
    assert credential_can_verify(revoked, now_epoch=120) is False
    assert active.status == "active"
    assert active.activated_at_epoch == 120
    assert active.expires_at_epoch is None
    assert credential_can_verify(active, now_epoch=120) is True


def test_revoked_credential_cannot_be_reactivated_as_current() -> None:
    current = new_active_credential(_credential(0x55), now_epoch=100)
    pending = new_pending_credential(_credential(0x66), now_epoch=110, expires_at_epoch=200)
    revoked, active = activate_replacement(current, pending, now_epoch=120)
    next_pending = new_pending_credential(_credential(0x77), now_epoch=130, expires_at_epoch=220)

    with pytest.raises(AgentSignatureError, match="current credential is not active"):
        activate_replacement(revoked, next_pending, now_epoch=140)

    _, next_active = activate_replacement(active, next_pending, now_epoch=140)
    assert credential_can_verify(next_active, now_epoch=140) is True


def test_expired_pending_credential_never_becomes_active() -> None:
    current = new_active_credential(_credential(0x55), now_epoch=100)
    pending = new_pending_credential(_credential(0x66), now_epoch=110, expires_at_epoch=120)
    expired = expire_pending(pending, now_epoch=121)
    assert expired.status == "expired"
    assert credential_can_verify(expired, now_epoch=121) is False
    with pytest.raises(AgentSignatureError, match="replacement credential is not pending"):
        activate_replacement(current, expired, now_epoch=121)


def test_cross_agent_replacement_is_rejected() -> None:
    current = new_active_credential(_credential(0x55, "agent-a"), now_epoch=100)
    pending = new_pending_credential(
        _credential(0x66, "agent-b"),
        now_epoch=110,
        expires_at_epoch=200,
    )
    with pytest.raises(AgentSignatureError, match="another agent"):
        activate_replacement(current, pending, now_epoch=120)


def test_public_credential_state_contains_no_private_key_field() -> None:
    state = new_active_credential(_credential(0x55), now_epoch=100)
    field_names = set(state.__dataclass_fields__)
    assert field_names == {
        "credential",
        "status",
        "created_at_epoch",
        "activated_at_epoch",
        "revoked_at_epoch",
        "expires_at_epoch",
    }
    assert "private" not in repr(state).lower()
