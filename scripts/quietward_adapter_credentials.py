from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


EVENT_INGESTION_SUBKEY_DOMAIN = b"quietward-response-event-ingestion-v1\0"
_MAX_CONFIG_BYTES = 64 * 1024
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


class AdapterCredentialError(RuntimeError):
    pass


def _derive_agent_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def derive_event_ingestion_subkey_from_secret(secret: str) -> bytes:
    return hmac.new(
        _derive_agent_hmac_key(secret),
        EVENT_INGESTION_SUBKEY_DOMAIN,
        hashlib.sha256,
    ).digest()


def _validate_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AdapterCredentialError("Response URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise AdapterCredentialError("Response URL must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise AdapterCredentialError("Response URL must not contain a path, query, or fragment")
    hostname = parsed.hostname.lower()
    loopback = hostname in _LOOPBACK_HOSTS or hostname.endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise AdapterCredentialError("plain HTTP is allowed only on loopback; use HTTPS otherwise")
    return normalized


def _private_json(path: Path) -> dict[str, Any]:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise AdapterCredentialError("credential path must be absolute")
    if resolved.is_symlink():
        raise AdapterCredentialError("credential file must not be a symbolic link")
    try:
        info = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise AdapterCredentialError(f"credential file is unavailable: {resolved}") from exc
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= _MAX_CONFIG_BYTES:
        raise AdapterCredentialError("credential file must be a bounded regular file")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise AdapterCredentialError("credential file must not be group/world accessible")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterCredentialError("credential file is unreadable or invalid JSON") from exc
    if not isinstance(value, dict):
        raise AdapterCredentialError("credential file must contain a JSON object")
    return value


def _atomic_private_json(path: Path, value: dict[str, Any], *, force: bool = False) -> None:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise AdapterCredentialError("adapter config path must be absolute")
    if resolved.exists() and not force:
        raise AdapterCredentialError(f"adapter config already exists: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = resolved.with_name(resolved.name + ".tmp")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short adapter credential write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, resolved)
    try:
        resolved.chmod(0o600)
    except OSError:
        pass


@dataclass(frozen=True, slots=True)
class AdapterCredential:
    base_url: str
    agent_id: str
    key_id: str
    host_id: str
    state_dir: Path
    event_subkey: bytes
    timeout_seconds: float = 5.0

    @classmethod
    def from_file(cls, path: Path) -> "AdapterCredential":
        value = _private_json(path)
        required = {
            "base_url": str(value.get("base_url") or "").strip(),
            "agent_id": str(value.get("agent_id") or "").strip(),
            "key_id": str(value.get("key_id") or "").strip(),
            "host_id": str(value.get("host_id") or "").strip(),
            "state_dir": str(value.get("state_dir") or "").strip(),
            "event_hmac_key_b64": str(value.get("event_hmac_key_b64") or "").strip(),
        }
        missing = [name for name, item in required.items() if not item]
        if missing:
            raise AdapterCredentialError("adapter credential is incomplete: " + ", ".join(missing))
        state_dir = Path(required["state_dir"]).expanduser()
        if not state_dir.is_absolute():
            raise AdapterCredentialError("adapter state directory must be absolute")
        try:
            event_subkey = base64.b64decode(required["event_hmac_key_b64"], validate=True)
        except Exception as exc:
            raise AdapterCredentialError("adapter event key encoding is invalid") from exc
        if len(event_subkey) != 32:
            raise AdapterCredentialError("adapter event key must be 32 bytes")
        timeout = float(value.get("timeout_seconds", 5.0))
        if not 0.1 <= timeout <= 60:
            raise AdapterCredentialError("adapter timeout must be between 0.1 and 60 seconds")
        return cls(
            base_url=_validate_base_url(required["base_url"]),
            agent_id=required["agent_id"],
            key_id=required["key_id"],
            host_id=required["host_id"],
            state_dir=state_dir,
            event_subkey=event_subkey,
            timeout_seconds=timeout,
        )


def provision_from_agent_config(
    agent_config_path: Path,
    adapter_config_path: Path,
    *,
    force: bool = False,
) -> Path:
    value = _private_json(agent_config_path)
    required = {
        "base_url": str(value.get("base_url") or "").strip(),
        "agent_id": str(value.get("agent_id") or "").strip(),
        "key_id": str(value.get("key_id") or "").strip(),
        "secret": str(value.get("secret") or "").strip(),
        "host_id": str(value.get("host_id") or "").strip(),
        "state_dir": str(value.get("state_dir") or "").strip(),
    }
    missing = [name for name, item in required.items() if not item]
    if missing:
        raise AdapterCredentialError("agent credential is incomplete: " + ", ".join(missing))
    state_dir = Path(required["state_dir"]).expanduser()
    if not state_dir.is_absolute():
        raise AdapterCredentialError("Response agent state directory must be absolute")
    event_key = derive_event_ingestion_subkey_from_secret(required["secret"])
    target = adapter_config_path.expanduser()
    _atomic_private_json(
        target,
        {
            "schema_version": "1.0",
            "credential_scope": "quietward_event_ingestion_only",
            "base_url": _validate_base_url(required["base_url"]),
            "agent_id": required["agent_id"],
            "key_id": required["key_id"],
            "host_id": required["host_id"],
            "state_dir": str(state_dir),
            "event_hmac_key_b64": base64.b64encode(event_key).decode("ascii"),
            "timeout_seconds": float(value.get("timeout_seconds", 5.0)),
        },
        force=force,
    )
    return target


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


class EventOnlyClient:
    """HMAC client whose key is accepted only for QuietWard event ingestion."""

    def __init__(self, config: AdapterCredential) -> None:
        self.config = config

    def _headers(self, method: str, target: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = os.urandom(16).hex()
        signature = hmac.new(
            self.config.event_subkey,
            _canonical_request(method, target, timestamp, nonce, body),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-QWR-Agent-ID": self.config.agent_id,
            "X-QWR-Key-ID": self.config.key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        }

    def _request(self, method: str, target: str, payload: dict[str, Any]) -> Any:
        if method.upper() != "POST" or target != "/api/v1/events":
            raise AdapterCredentialError("event-only credential refuses non-event endpoint")
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = Request(
            self.config.base_url + target,
            data=body,
            method="POST",
            headers=self._headers("POST", target, body),
        )
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:2000]
            raise AdapterCredentialError(
                f"Response API HTTP {exc.code} for POST {target}: {detail}"
            ) from exc
        except (URLError, OSError) as exc:
            raise AdapterCredentialError(f"Response API unavailable: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AdapterCredentialError("Response API returned invalid JSON") from exc
