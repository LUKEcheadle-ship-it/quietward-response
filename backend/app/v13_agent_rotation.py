from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Final

from app.v13_agent_signature import (
    AgentSignatureError,
    _b64url_decode,
    key_id_for_public_key,
)


ROTATION_PROTOCOL: Final[str] = "qwr-agent-key-rotation-v1"


@dataclass(frozen=True, slots=True)
class RotationProposal:
    agent_id: str
    current_key_id: str
    replacement_key_id: str
    replacement_public_key_b64: str
    challenge: str
    expires_at_epoch: int

    def __post_init__(self) -> None:
        replacement = _b64url_decode(
            self.replacement_public_key_b64,
            expected_bytes=32,
            label="replacement public key",
        )
        if key_id_for_public_key(replacement) != self.replacement_key_id:
            raise AgentSignatureError("replacement public key does not match replacement_key_id")
        if not 1 <= len(self.agent_id) <= 64:
            raise AgentSignatureError("rotation agent_id is invalid")
        if not self.current_key_id.startswith("qwrpk1_") or len(self.current_key_id) != 39:
            raise AgentSignatureError("current key identifier is invalid")
        if self.replacement_key_id == self.current_key_id:
            raise AgentSignatureError("replacement key must differ from current key")
        if not 16 <= len(self.challenge) <= 128 or "\n" in self.challenge or "\r" in self.challenge:
            raise AgentSignatureError("rotation challenge is invalid")
        if not isinstance(self.expires_at_epoch, int) or self.expires_at_epoch <= 0:
            raise AgentSignatureError("rotation expiry is invalid")


def _canonical(proposal: RotationProposal, phase: str) -> bytes:
    if phase not in {"prepare", "activate"}:
        raise AgentSignatureError("rotation phase is invalid")
    replacement_raw = _b64url_decode(
        proposal.replacement_public_key_b64,
        expected_bytes=32,
        label="replacement public key",
    )
    replacement_hash = hashlib.sha256(replacement_raw).hexdigest()
    return "\n".join(
        (
            ROTATION_PROTOCOL,
            phase,
            proposal.agent_id,
            proposal.current_key_id,
            proposal.replacement_key_id,
            replacement_hash,
            proposal.challenge,
            str(proposal.expires_at_epoch),
        )
    ).encode("utf-8")


def canonical_rotation_prepare(proposal: RotationProposal) -> bytes:
    return _canonical(proposal, "prepare")


def canonical_rotation_activate(proposal: RotationProposal) -> bytes:
    return _canonical(proposal, "activate")


def _verify_raw_signature(
    *,
    public_key_b64: str,
    expected_key_id: str,
    signature_b64: str,
    message: bytes,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - dedicated v1.3 environment
        raise AgentSignatureError(
            "v1.3 Ed25519 rotation verification requires cryptography"
        ) from exc

    public_raw = _b64url_decode(public_key_b64, expected_bytes=32, label="public key")
    if key_id_for_public_key(public_raw) != expected_key_id:
        raise AgentSignatureError("rotation verification public key does not match key_id")
    signature = _b64url_decode(signature_b64, expected_bytes=64, label="signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise AgentSignatureError("rotation signature is invalid") from exc


def verify_rotation_prepare(
    *,
    proposal: RotationProposal,
    current_public_key_b64: str,
    current_signature_b64: str,
    now_epoch: int,
) -> None:
    if now_epoch > proposal.expires_at_epoch:
        raise AgentSignatureError("rotation proposal has expired")
    _verify_raw_signature(
        public_key_b64=current_public_key_b64,
        expected_key_id=proposal.current_key_id,
        signature_b64=current_signature_b64,
        message=canonical_rotation_prepare(proposal),
    )


def verify_rotation_activation(
    *,
    proposal: RotationProposal,
    replacement_signature_b64: str,
    now_epoch: int,
) -> None:
    if now_epoch > proposal.expires_at_epoch:
        raise AgentSignatureError("rotation proposal has expired")
    _verify_raw_signature(
        public_key_b64=proposal.replacement_public_key_b64,
        expected_key_id=proposal.replacement_key_id,
        signature_b64=replacement_signature_b64,
        message=canonical_rotation_activate(proposal),
    )
