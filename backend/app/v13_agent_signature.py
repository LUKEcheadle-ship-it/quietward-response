from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import Final


PROTOCOL_VERSION: Final[str] = "qwr-agent-signature-v1"
_KEY_ID_RE = re.compile(r"^qwrpk1_[0-9a-f]{32}$")


class AgentSignatureError(ValueError):
    pass


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise AgentSignatureError(f"{label} encoding is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise AgentSignatureError(f"{label} encoding is invalid") from exc
    if len(decoded) != expected_bytes:
        raise AgentSignatureError(f"{label} length is invalid")
    return decoded


def key_id_for_public_key(public_key_raw: bytes) -> str:
    if len(public_key_raw) != 32:
        raise AgentSignatureError("Ed25519 public key must be exactly 32 bytes")
    return "qwrpk1_" + hashlib.sha256(public_key_raw).hexdigest()[:32]


def canonical_agent_message(
    *,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    agent_id: str,
    key_id: str,
) -> bytes:
    method = method.strip().upper()
    target = target.strip()
    timestamp = timestamp.strip()
    nonce = nonce.strip()
    agent_id = agent_id.strip()
    key_id = key_id.strip()

    if not method or len(method) > 16 or not method.isascii():
        raise AgentSignatureError("HTTP method is invalid")
    if not target.startswith("/") or len(target) > 4096 or "\n" in target or "\r" in target:
        raise AgentSignatureError("canonical target is invalid")
    if not timestamp.isdigit() or len(timestamp) > 20:
        raise AgentSignatureError("timestamp is invalid")
    if not 16 <= len(nonce) <= 128 or "\n" in nonce or "\r" in nonce:
        raise AgentSignatureError("nonce is invalid")
    if not 1 <= len(agent_id) <= 64 or "\n" in agent_id or "\r" in agent_id:
        raise AgentSignatureError("agent_id is invalid")
    if not _KEY_ID_RE.fullmatch(key_id):
        raise AgentSignatureError("public key identifier is invalid")

    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join(
        (
            PROTOCOL_VERSION,
            method,
            target,
            timestamp,
            nonce,
            agent_id,
            key_id,
            body_hash,
        )
    ).encode("utf-8")


def verify_ed25519_signature(
    *,
    public_key_b64: str,
    signature_b64: str,
    method: str,
    target: str,
    timestamp: str,
    nonce: str,
    body: bytes,
    agent_id: str,
    key_id: str,
) -> None:
    """Verify a v1.3 candidate request using public key material only.

    The import is intentionally local so the v1.2 application does not gain a new
    runtime dependency merely by carrying the isolated v1.3 protocol prototype.
    A v1.3 release must promote `cryptography` into the normal pinned dependency
    set and qualify it on every supported platform before this protocol is enabled.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised by dedicated v1.3 environment
        raise AgentSignatureError(
            "v1.3 Ed25519 verification requires the vetted cryptography dependency"
        ) from exc

    public_key_raw = _b64url_decode(public_key_b64, expected_bytes=32, label="public key")
    expected_key_id = key_id_for_public_key(public_key_raw)
    if expected_key_id != key_id:
        raise AgentSignatureError("public key does not match key_id")
    signature = _b64url_decode(signature_b64, expected_bytes=64, label="signature")
    message = canonical_agent_message(
        method=method,
        target=target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        agent_id=agent_id,
        key_id=key_id,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(signature, message)
    except InvalidSignature as exc:
        raise AgentSignatureError("Ed25519 signature is invalid") from exc


@dataclass(frozen=True, slots=True)
class PublicAgentCredential:
    agent_id: str
    key_id: str
    public_key_b64: str
    algorithm: str = "Ed25519"
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        public_key = _b64url_decode(
            self.public_key_b64,
            expected_bytes=32,
            label="public key",
        )
        expected = key_id_for_public_key(public_key)
        if expected != self.key_id:
            raise AgentSignatureError("public credential key_id does not match public key")
        if not 1 <= len(self.agent_id) <= 64:
            raise AgentSignatureError("public credential agent_id is invalid")
        if self.algorithm != "Ed25519":
            raise AgentSignatureError("unsupported public credential algorithm")
        if self.protocol_version != PROTOCOL_VERSION:
            raise AgentSignatureError("unsupported agent signature protocol")
