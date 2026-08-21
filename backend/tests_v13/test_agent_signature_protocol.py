from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.v13_agent_signature import (
    AgentSignatureError,
    PublicAgentCredential,
    canonical_agent_message,
    key_id_for_public_key,
    verify_ed25519_signature,
)


SEED = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _credential():
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = key_id_for_public_key(public_raw)
    return private, public_raw, key_id


def _signed_request(**overrides):
    private, public_raw, key_id = _credential()
    values = {
        "method": "POST",
        "target": "/api/v1/actions/00000000-0000-0000-0000-000000000001/result?mode=terminal",
        "timestamp": "1787353200",
        "nonce": "0123456789abcdef0123456789abcdef",
        "body": b'{"status":"succeeded"}',
        "agent_id": "agent-v13-test",
        "key_id": key_id,
    }
    values.update(overrides)
    message = canonical_agent_message(**values)
    signature = private.sign(message)
    return values, _b64(public_raw), _b64(signature)


def test_public_credential_contains_no_private_material_and_binds_key_id() -> None:
    _, public_raw, key_id = _credential()
    credential = PublicAgentCredential(
        agent_id="agent-v13-test",
        key_id=key_id,
        public_key_b64=_b64(public_raw),
    )
    assert credential.algorithm == "Ed25519"
    assert credential.protocol_version == "qwr-agent-signature-v1"
    assert set(credential.__dataclass_fields__) == {
        "agent_id",
        "key_id",
        "public_key_b64",
        "algorithm",
        "protocol_version",
    }


def test_valid_ed25519_request_verifies_with_public_key_only() -> None:
    values, public_key_b64, signature_b64 = _signed_request()
    verify_ed25519_signature(
        public_key_b64=public_key_b64,
        signature_b64=signature_b64,
        **values,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("method", "PATCH"),
        ("target", "/api/v1/agents/other/actions/pending"),
        ("timestamp", "1787353201"),
        ("nonce", "fedcba9876543210fedcba9876543210"),
        ("body", b'{"status":"failed"}'),
        ("agent_id", "agent-v13-other"),
    ],
)
def test_signed_request_rejects_canonical_field_substitution(field: str, replacement) -> None:
    values, public_key_b64, signature_b64 = _signed_request()
    values[field] = replacement
    with pytest.raises(AgentSignatureError, match="signature is invalid"):
        verify_ed25519_signature(
            public_key_b64=public_key_b64,
            signature_b64=signature_b64,
            **values,
        )


def test_public_key_substitution_fails_before_signature_acceptance() -> None:
    values, _, signature_b64 = _signed_request()
    other = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
    other_public = other.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    with pytest.raises(AgentSignatureError, match="public key does not match key_id"):
        verify_ed25519_signature(
            public_key_b64=_b64(other_public),
            signature_b64=signature_b64,
            **values,
        )


def test_key_id_is_deterministic_public_key_fingerprint() -> None:
    _, public_raw, key_id = _credential()
    assert key_id.startswith("qwrpk1_")
    assert len(key_id) == len("qwrpk1_") + 32
    assert key_id_for_public_key(public_raw) == key_id


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target": "https://example.test/not-a-target"},
        {"timestamp": "not-epoch"},
        {"nonce": "short"},
        {"agent_id": ""},
        {"key_id": "not-a-key-id"},
    ],
)
def test_canonical_message_rejects_ambiguous_or_unbounded_fields(kwargs: dict) -> None:
    values, _, _ = _signed_request()
    values.update(kwargs)
    with pytest.raises(AgentSignatureError):
        canonical_agent_message(**values)


def test_malformed_public_key_and_signature_encodings_fail_closed() -> None:
    values, public_key_b64, signature_b64 = _signed_request()
    with pytest.raises(AgentSignatureError):
        verify_ed25519_signature(
            public_key_b64="not-base64!",
            signature_b64=signature_b64,
            **values,
        )
    with pytest.raises(AgentSignatureError):
        verify_ed25519_signature(
            public_key_b64=public_key_b64,
            signature_b64="too-short",
            **values,
        )
