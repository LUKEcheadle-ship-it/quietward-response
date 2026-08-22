#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class EndpointIdentityError(RuntimeError):
    pass


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - dedicated v1.3 environment
        raise EndpointIdentityError(
            "v1.3 endpoint identity requires the vetted cryptography dependency"
        ) from exc
    return serialization, Ed25519PrivateKey


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str, expected: int, label: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise EndpointIdentityError(f"invalid {label} encoding") from exc
    if len(raw) != expected:
        raise EndpointIdentityError(f"invalid {label} length")
    return raw


def _public_material(private_key) -> tuple[bytes, str]:
    serialization, _ = _crypto()
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Importing the public helper does not expose the private key to server code;
    # this endpoint module only reuses the deterministic public-key fingerprint.
    from app.v13_agent_signature import key_id_for_public_key

    return public_raw, key_id_for_public_key(public_raw)


@dataclass(slots=True)
class EndpointIdentity:
    agent_id: str
    _private_key: Any

    def __post_init__(self) -> None:
        if not 1 <= len(self.agent_id) <= 64:
            raise EndpointIdentityError("agent_id is invalid")
        public_raw, key_id = _public_material(self._private_key)
        self.public_key_b64 = _b64(public_raw)
        self.key_id = key_id

    @classmethod
    def generate(cls, *, agent_id: str) -> "EndpointIdentity":
        _, private_cls = _crypto()
        return cls(agent_id=agent_id, _private_key=private_cls.generate())

    @classmethod
    def from_private_bytes(cls, *, agent_id: str, private_key_raw: bytes) -> "EndpointIdentity":
        if len(private_key_raw) != 32:
            raise EndpointIdentityError("Ed25519 private key seed must be exactly 32 bytes")
        _, private_cls = _crypto()
        return cls(agent_id=agent_id, _private_key=private_cls.from_private_bytes(private_key_raw))

    def sign(self, message: bytes) -> str:
        if not isinstance(message, bytes) or not message:
            raise EndpointIdentityError("signature message must be non-empty bytes")
        return _b64(self._private_key.sign(message))

    def sign_request(
        self,
        *,
        method: str,
        target: str,
        timestamp: str,
        nonce: str,
        body: bytes,
    ) -> str:
        from app.v13_agent_signature import canonical_agent_message

        return self.sign(
            canonical_agent_message(
                method=method,
                target=target,
                timestamp=timestamp,
                nonce=nonce,
                body=body,
                agent_id=self.agent_id,
                key_id=self.key_id,
            )
        )

    def private_key_bytes_for_secure_store(self) -> bytes:
        """Return the raw seed only to an endpoint-side secure-store adapter.

        Production code must not log, transmit, or place this value in the Response
        database. The v1.3 production design must use an OS-backed/private endpoint
        store rather than the development file helper below.
        """
        serialization, _ = _crypto()
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


@dataclass(frozen=True, slots=True)
class DevelopmentIdentityFile:
    schema_version: str
    agent_id: str
    key_id: str
    public_key_b64: str
    private_key_b64: str


_DEV_FILE_SCHEMA = "v13-dev-ed25519-file-v1"


def write_development_identity_file(
    path: Path,
    identity: EndpointIdentity,
    *,
    force: bool = False,
    explicitly_allow_development_file_store: bool = False,
) -> Path:
    """Development-only private key persistence.

    This helper intentionally requires an explicit opt-in and is prohibited for a
    production v1.3 release. It exists only so the isolated protocol prototype can
    test restart/rotation semantics before OS-backed stores are qualified.
    """
    if not explicitly_allow_development_file_store:
        raise EndpointIdentityError(
            "development private-key file store requires explicit opt-in"
        )
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise EndpointIdentityError("development identity path must be absolute")
    if resolved.exists() and not force:
        raise EndpointIdentityError("development identity file already exists")
    if resolved.exists() and resolved.is_symlink():
        raise EndpointIdentityError("development identity file must not be a symlink")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_raw = identity.private_key_bytes_for_secure_store()
    payload = {
        "schema_version": _DEV_FILE_SCHEMA,
        "agent_id": identity.agent_id,
        "key_id": identity.key_id,
        "public_key_b64": identity.public_key_b64,
        "private_key_b64": _b64(private_raw),
    }
    temporary = resolved.with_name(resolved.name + ".tmp")
    raw = (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short development identity write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, resolved)
    try:
        resolved.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return resolved


def load_development_identity_file(
    path: Path,
    *,
    explicitly_allow_development_file_store: bool = False,
) -> EndpointIdentity:
    if not explicitly_allow_development_file_store:
        raise EndpointIdentityError(
            "development private-key file store requires explicit opt-in"
        )
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise EndpointIdentityError("development identity path must be absolute")
    if resolved.is_symlink():
        raise EndpointIdentityError("development identity file must not be a symlink")
    try:
        info = resolved.stat()
        raw = resolved.read_bytes()
    except OSError as exc:
        raise EndpointIdentityError("unable to read development identity file") from exc
    if not stat.S_ISREG(info.st_mode):
        raise EndpointIdentityError("development identity path must be a regular file")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise EndpointIdentityError("development identity file must be mode 0600 or stricter")
    if len(raw) > 4096:
        raise EndpointIdentityError("development identity file is unexpectedly large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EndpointIdentityError("development identity file is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("schema_version") != _DEV_FILE_SCHEMA:
        raise EndpointIdentityError("development identity schema is invalid")
    expected_fields = {
        "schema_version",
        "agent_id",
        "key_id",
        "public_key_b64",
        "private_key_b64",
    }
    if set(value) != expected_fields:
        raise EndpointIdentityError("development identity field set is invalid")
    private_raw = _decode(str(value["private_key_b64"]), 32, "private key")
    identity = EndpointIdentity.from_private_bytes(
        agent_id=str(value["agent_id"]),
        private_key_raw=private_raw,
    )
    if identity.key_id != value["key_id"] or identity.public_key_b64 != value["public_key_b64"]:
        raise EndpointIdentityError("development identity public/private material mismatch")
    return identity
