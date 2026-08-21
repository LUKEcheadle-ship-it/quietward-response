from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.v13_agent_enrollment import (
    EnrollmentChallenge,
    canonical_enrollment_proof,
    verify_enrollment_key_possession,
)
from app.v13_agent_signature import AgentSignatureError, key_id_for_public_key


SEED = bytes.fromhex("33" * 32)
OTHER_SEED = bytes.fromhex("44" * 32)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _key(seed: bytes):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private, public, key_id_for_public_key(public)


def _challenge(**overrides) -> EnrollmentChallenge:
    values = {
        "enrollment_id": "enroll-0123456789abcdef",
        "host_id": "host-v13-enrollment",
        "challenge": "0123456789abcdef0123456789abcdef",
        "expires_at_epoch": 2_000_000_000,
    }
    values.update(overrides)
    return EnrollmentChallenge(**values)


def _proof(enrollment: EnrollmentChallenge):
    private, public, key_id = _key(SEED)
    public_b64 = _b64(public)
    message = canonical_enrollment_proof(
        enrollment=enrollment,
        public_key_b64=public_b64,
        key_id=key_id,
    )
    return public_b64, key_id, _b64(private.sign(message))


def test_endpoint_generated_key_can_prove_possession_for_enrollment() -> None:
    enrollment = _challenge()
    public_b64, key_id, signature = _proof(enrollment)
    verify_enrollment_key_possession(
        enrollment=enrollment,
        public_key_b64=public_b64,
        key_id=key_id,
        signature_b64=signature,
        now_epoch=1_900_000_000,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("enrollment_id", "enroll-fedcba9876543210"),
        ("host_id", "host-v13-other"),
        ("challenge", "fedcba9876543210fedcba9876543210"),
        ("expires_at_epoch", 2_000_000_001),
    ],
)
def test_enrollment_proof_binds_challenge_and_target_fields(field: str, replacement) -> None:
    original = _challenge()
    public_b64, key_id, signature = _proof(original)
    changed = _challenge(**{field: replacement})
    with pytest.raises(AgentSignatureError, match="signature is invalid"):
        verify_enrollment_key_possession(
            enrollment=changed,
            public_key_b64=public_b64,
            key_id=key_id,
            signature_b64=signature,
            now_epoch=1_900_000_000,
        )


def test_different_private_key_cannot_claim_another_public_key() -> None:
    enrollment = _challenge()
    _, public, key_id = _key(SEED)
    other_private, _, _ = _key(OTHER_SEED)
    public_b64 = _b64(public)
    forged = _b64(
        other_private.sign(
            canonical_enrollment_proof(
                enrollment=enrollment,
                public_key_b64=public_b64,
                key_id=key_id,
            )
        )
    )
    with pytest.raises(AgentSignatureError, match="signature is invalid"):
        verify_enrollment_key_possession(
            enrollment=enrollment,
            public_key_b64=public_b64,
            key_id=key_id,
            signature_b64=forged,
            now_epoch=1_900_000_000,
        )


def test_enrollment_key_id_must_match_submitted_public_key() -> None:
    enrollment = _challenge()
    _, public, _ = _key(SEED)
    with pytest.raises(AgentSignatureError, match="public key does not match key_id"):
        canonical_enrollment_proof(
            enrollment=enrollment,
            public_key_b64=_b64(public),
            key_id="qwrpk1_" + "0" * 32,
        )


def test_expired_enrollment_challenge_is_rejected() -> None:
    enrollment = _challenge(expires_at_epoch=1_900_000_000)
    public_b64, key_id, signature = _proof(enrollment)
    with pytest.raises(AgentSignatureError, match="expired"):
        verify_enrollment_key_possession(
            enrollment=enrollment,
            public_key_b64=public_b64,
            key_id=key_id,
            signature_b64=signature,
            now_epoch=1_900_000_001,
        )
