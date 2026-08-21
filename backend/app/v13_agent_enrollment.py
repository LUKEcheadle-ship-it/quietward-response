from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from app.v13_agent_signature import AgentSignatureError, _b64url_decode, key_id_for_public_key


ENROLLMENT_PROTOCOL: Final[str] = "qwr-agent-enrollment-v1"


@dataclass(frozen=True, slots=True)
class EnrollmentChallenge:
    enrollment_id: str
    host_id: str
    challenge: str
    expires_at_epoch: int

    def __post_init__(self) -> None:
        if not 16 <= len(self.enrollment_id) <= 128 or "\n" in self.enrollment_id:
            raise AgentSignatureError("enrollment_id is invalid")
        if not 1 <= len(self.host_id) <= 128 or "\n" in self.host_id or "\r" in self.host_id:
            raise AgentSignatureError("enrollment host_id is invalid")
        if not 16 <= len(self.challenge) <= 128 or "\n" in self.challenge or "\r" in self.challenge:
            raise AgentSignatureError("enrollment challenge is invalid")
        if not isinstance(self.expires_at_epoch, int) or self.expires_at_epoch <= 0:
            raise AgentSignatureError("enrollment expiry is invalid")


def canonical_enrollment_proof(
    *,
    enrollment: EnrollmentChallenge,
    public_key_b64: str,
    key_id: str,
) -> bytes:
    public_raw = _b64url_decode(public_key_b64, expected_bytes=32, label="public key")
    if key_id_for_public_key(public_raw) != key_id:
        raise AgentSignatureError("enrollment public key does not match key_id")
    public_hash = hashlib.sha256(public_raw).hexdigest()
    return "\n".join(
        (
            ENROLLMENT_PROTOCOL,
            enrollment.enrollment_id,
            enrollment.host_id,
            enrollment.challenge,
            str(enrollment.expires_at_epoch),
            key_id,
            public_hash,
        )
    ).encode("utf-8")


def verify_enrollment_key_possession(
    *,
    enrollment: EnrollmentChallenge,
    public_key_b64: str,
    key_id: str,
    signature_b64: str,
    now_epoch: int,
) -> None:
    if now_epoch > enrollment.expires_at_epoch:
        raise AgentSignatureError("enrollment challenge has expired")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - dedicated v1.3 environment
        raise AgentSignatureError(
            "v1.3 Ed25519 enrollment verification requires cryptography"
        ) from exc

    public_raw = _b64url_decode(public_key_b64, expected_bytes=32, label="public key")
    if key_id_for_public_key(public_raw) != key_id:
        raise AgentSignatureError("enrollment public key does not match key_id")
    signature = _b64url_decode(signature_b64, expected_bytes=64, label="signature")
    message = canonical_enrollment_proof(
        enrollment=enrollment,
        public_key_b64=public_key_b64,
        key_id=key_id,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise AgentSignatureError("enrollment key-possession signature is invalid") from exc
