from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.v13_agent_rotation import (
    RotationProposal,
    canonical_rotation_activate,
    canonical_rotation_prepare,
    verify_rotation_activation,
    verify_rotation_prepare,
)
from app.v13_agent_signature import AgentSignatureError, key_id_for_public_key


CURRENT_SEED = bytes.fromhex("11" * 32)
REPLACEMENT_SEED = bytes.fromhex("22" * 32)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key(seed: bytes):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public, key_id_for_public_key(public)


def _proposal(**overrides):
    _, _, current_id = _key(CURRENT_SEED)
    _, replacement_public, replacement_id = _key(REPLACEMENT_SEED)
    values = {
        "agent_id": "agent-v13-rotation",
        "current_key_id": current_id,
        "replacement_key_id": replacement_id,
        "replacement_public_key_b64": _b64(replacement_public),
        "challenge": "0123456789abcdef0123456789abcdef",
        "expires_at_epoch": 2_000_000_000,
    }
    values.update(overrides)
    return RotationProposal(**values)


def _proofs(proposal: RotationProposal):
    current_private, current_public, _ = _key(CURRENT_SEED)
    replacement_private, _, _ = _key(REPLACEMENT_SEED)
    prepare = _b64(current_private.sign(canonical_rotation_prepare(proposal)))
    activate = _b64(replacement_private.sign(canonical_rotation_activate(proposal)))
    return _b64(current_public), prepare, activate


def test_rotation_requires_valid_current_key_authorization_and_new_key_possession() -> None:
    proposal = _proposal()
    current_public, prepare_signature, activation_signature = _proofs(proposal)

    verify_rotation_prepare(
        proposal=proposal,
        current_public_key_b64=current_public,
        current_signature_b64=prepare_signature,
        now_epoch=1_900_000_000,
    )
    verify_rotation_activation(
        proposal=proposal,
        replacement_signature_b64=activation_signature,
        now_epoch=1_900_000_000,
    )


def test_replacement_private_key_cannot_authorize_its_own_prepare() -> None:
    proposal = _proposal()
    _, current_public_raw, _ = _key(CURRENT_SEED)
    replacement_private, _, _ = _key(REPLACEMENT_SEED)
    forged_prepare = _b64(replacement_private.sign(canonical_rotation_prepare(proposal)))
    with pytest.raises(AgentSignatureError, match="rotation signature is invalid"):
        verify_rotation_prepare(
            proposal=proposal,
            current_public_key_b64=_b64(current_public_raw),
            current_signature_b64=forged_prepare,
            now_epoch=1_900_000_000,
        )


def test_current_private_key_cannot_fake_replacement_possession() -> None:
    proposal = _proposal()
    current_private, _, _ = _key(CURRENT_SEED)
    forged_activation = _b64(current_private.sign(canonical_rotation_activate(proposal)))
    with pytest.raises(AgentSignatureError, match="rotation signature is invalid"):
        verify_rotation_activation(
            proposal=proposal,
            replacement_signature_b64=forged_activation,
            now_epoch=1_900_000_000,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("agent_id", "agent-other"),
        ("challenge", "fedcba9876543210fedcba9876543210"),
        ("expires_at_epoch", 2_000_000_001),
    ],
)
def test_rotation_prepare_signature_binds_proposal_fields(field: str, replacement) -> None:
    original = _proposal()
    current_public, prepare_signature, _ = _proofs(original)
    changed = _proposal(**{field: replacement})
    with pytest.raises(AgentSignatureError, match="rotation signature is invalid"):
        verify_rotation_prepare(
            proposal=changed,
            current_public_key_b64=current_public,
            current_signature_b64=prepare_signature,
            now_epoch=1_900_000_000,
        )


def test_rotation_proposal_expiry_blocks_both_proofs() -> None:
    proposal = _proposal(expires_at_epoch=1_900_000_000)
    current_public, prepare_signature, activation_signature = _proofs(proposal)
    with pytest.raises(AgentSignatureError, match="expired"):
        verify_rotation_prepare(
            proposal=proposal,
            current_public_key_b64=current_public,
            current_signature_b64=prepare_signature,
            now_epoch=1_900_000_001,
        )
    with pytest.raises(AgentSignatureError, match="expired"):
        verify_rotation_activation(
            proposal=proposal,
            replacement_signature_b64=activation_signature,
            now_epoch=1_900_000_001,
        )


def test_replacement_key_id_must_match_replacement_public_key() -> None:
    _, _, current_id = _key(CURRENT_SEED)
    _, replacement_public, _ = _key(REPLACEMENT_SEED)
    with pytest.raises(AgentSignatureError, match="replacement public key does not match"):
        RotationProposal(
            agent_id="agent-v13-rotation",
            current_key_id=current_id,
            replacement_key_id="qwrpk1_" + "0" * 32,
            replacement_public_key_b64=_b64(replacement_public),
            challenge="0123456789abcdef0123456789abcdef",
            expires_at_epoch=2_000_000_000,
        )
