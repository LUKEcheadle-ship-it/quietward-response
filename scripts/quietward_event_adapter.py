#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import signal
import sqlite3
import stat
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import NAMESPACE_URL, uuid5


class QuietWardAdapterError(RuntimeError):
    pass


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_MAX_CONFIG_BYTES = 64 * 1024
_DEFAULT_BATCH = 100
_MAX_BATCH = 500

_CATEGORY_BY_KIND = {
    "malware_signature": "malware",
    "yara_match": "malware",
    "executable_created": "execution",
    "process_start": "execution",
    "privilege_escalation": "privilege",
    "auth_failure": "identity",
    "account_change": "identity",
    "persistence_change": "persistence",
    "new_listening_port": "network",
    "outbound_connection": "network",
    "sensitive_file_change": "file_integrity",
    "file_change": "file_integrity",
    "container_escape_indicator": "container",
    "container_configuration_change": "container",
    "container_change": "container",
    "package_vulnerability": "vulnerability",
    "configuration_weakness": "vulnerability",
    "self_integrity_change": "integrity",
    "evidence_integrity_failure": "integrity",
    "collector_health": "operational",
}


def _validate_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise QuietWardAdapterError("Response URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise QuietWardAdapterError("Response URL must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise QuietWardAdapterError("Response URL must not contain a path, query, or fragment")
    hostname = parsed.hostname.lower()
    loopback = hostname in _LOOPBACK_HOSTS or hostname.endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise QuietWardAdapterError("plain HTTP is allowed only on loopback; use HTTPS otherwise")
    return normalized


def _private_json(path: Path) -> dict[str, Any]:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise QuietWardAdapterError("adapter config path must be absolute")
    if resolved.is_symlink():
        raise QuietWardAdapterError("adapter config must not be a symbolic link")
    try:
        info = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise QuietWardAdapterError(f"adapter config is unavailable: {resolved}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > _MAX_CONFIG_BYTES:
        raise QuietWardAdapterError("adapter config must be a bounded regular file")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise QuietWardAdapterError("adapter config must not be group/world accessible")
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QuietWardAdapterError("adapter config is unreadable or invalid JSON") from exc
    if not isinstance(value, dict):
        raise QuietWardAdapterError("adapter config must be a JSON object")
    return value


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    base_url: str
    agent_id: str
    key_id: str
    secret: str
    host_id: str
    state_dir: Path
    quietward_db_path: Path
    timeout_seconds: float = 5.0

    @classmethod
    def from_agent_config(
        cls,
        path: Path,
        *,
        quietward_db_path: Path | None = None,
    ) -> "AdapterConfig":
        value = _private_json(path)
        required = {
            "base_url": str(value.get("base_url") or "").strip(),
            "agent_id": str(value.get("agent_id") or "").strip(),
            "key_id": str(value.get("key_id") or "").strip(),
            "secret": str(value.get("secret") or "").strip(),
            "host_id": str(value.get("host_id") or "").strip(),
            "state_dir": str(value.get("state_dir") or "").strip(),
        }
        missing = [key for key, item in required.items() if not item]
        if missing:
            raise QuietWardAdapterError(
                "agent config is incomplete for the adapter: " + ", ".join(missing)
            )
        state_dir = Path(required["state_dir"]).expanduser()
        if not state_dir.is_absolute():
            raise QuietWardAdapterError("Response agent state directory must be absolute")
        db_path = (
            quietward_db_path.expanduser()
            if quietward_db_path is not None
            else Path("~/.local/state/quietward/quietward.sqlite3").expanduser()
        )
        if not db_path.is_absolute():
            raise QuietWardAdapterError("QuietWard database path must be absolute")
        timeout = float(value.get("timeout_seconds", 5.0))
        if not 0.1 <= timeout <= 60:
            raise QuietWardAdapterError("adapter timeout must be between 0.1 and 60 seconds")
        return cls(
            base_url=_validate_base_url(required["base_url"]),
            agent_id=required["agent_id"],
            key_id=required["key_id"],
            secret=required["secret"],
            host_id=required["host_id"],
            state_dir=state_dir,
            quietward_db_path=db_path,
            timeout_seconds=timeout,
        )


@dataclass(frozen=True, slots=True)
class QuietWardRow:
    rowid: int
    event_id: str
    observed_at: str
    host_id: str
    source: str
    kind: str
    subject: str
    severity: str
    score: float | None
    payload: dict[str, Any]


def _open_quietward_read_only(path: Path) -> sqlite3.Connection:
    if path.is_symlink():
        raise QuietWardAdapterError("QuietWard database path must not be a symbolic link")
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise QuietWardAdapterError(f"QuietWard database is unavailable: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise QuietWardAdapterError("QuietWard database must be a regular file")
    uri = "file:" + str(path) + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def read_rows(path: Path, *, after_rowid: int, limit: int = _DEFAULT_BATCH) -> list[QuietWardRow]:
    bounded = max(1, min(int(limit), _MAX_BATCH))
    with _open_quietward_read_only(path) as connection:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        required = {
            "event_id",
            "observed_at",
            "host_id",
            "source",
            "kind",
            "subject",
            "severity",
            "score",
            "payload_json",
        }
        if not required.issubset(columns):
            raise QuietWardAdapterError("QuietWard events schema is incompatible with adapter v1")
        rows = connection.execute(
            """
            SELECT rowid,event_id,observed_at,host_id,source,kind,subject,
                   severity,score,payload_json
            FROM events
            WHERE rowid>?
            ORDER BY rowid ASC
            LIMIT ?
            """,
            (max(0, int(after_rowid)), bounded),
        ).fetchall()

    result: list[QuietWardRow] = []
    for row in rows:
        try:
            payload = json.loads(str(row[9]))
        except json.JSONDecodeError as exc:
            raise QuietWardAdapterError(
                f"QuietWard event payload is invalid JSON at rowid {row[0]}"
            ) from exc
        if not isinstance(payload, dict):
            raise QuietWardAdapterError(
                f"QuietWard event payload must be an object at rowid {row[0]}"
            )
        result.append(
            QuietWardRow(
                rowid=int(row[0]),
                event_id=str(row[1]),
                observed_at=str(row[2]),
                host_id=str(row[3]),
                source=str(row[4]),
                kind=str(row[5]).strip().lower(),
                subject=str(row[6]),
                severity=str(row[7] or "informational").strip().lower(),
                score=float(row[8]) if row[8] is not None else None,
                payload=payload,
            )
        )
    return result


def _typed_sections(kind: str, subject: str, attributes: dict[str, Any]) -> dict[str, Any]:
    process = file_value = network = persistence = None
    if kind in {"process_start", "privilege_escalation", "executable_created"}:
        process = {
            key: attributes[key]
            for key in ("pid", "ppid", "command_name", "args_hash", "privileged_context")
            if key in attributes
        }
        process["image"] = str(attributes.get("command_name") or subject)[:512]
    if kind in {"sensitive_file_change", "file_change", "malware_signature", "yara_match"}:
        file_value = {
            "subject": subject[:1024],
            "sha256": attributes.get("current_sha256") or attributes.get("sha256"),
            "changed_fields": attributes.get("changed_fields"),
        }
    if kind in {"outbound_connection", "new_listening_port"}:
        network = {
            key: attributes[key]
            for key in (
                "protocol",
                "destination_hash",
                "destination_port",
                "destination_scope",
                "process_name",
                "local_address",
                "port",
                "external_bind",
            )
            if key in attributes
        }
        if "destination_hash" in network:
            network["remote_address_hash"] = network["destination_hash"]
    if kind in {"persistence_change", "account_change"}:
        persistence = {
            "subject": subject[:1024],
            "mechanism": attributes.get("category"),
            "current_fingerprint": attributes.get("current_fingerprint"),
            "risk_markers": attributes.get("risk_markers"),
        }
    return {
        "process": process,
        "file": file_value,
        "network": network,
        "persistence": persistence,
    }


def translate_row(row: QuietWardRow, *, expected_host_id: str) -> dict[str, Any]:
    if row.host_id != expected_host_id:
        raise QuietWardAdapterError(
            f"QuietWard row host {row.host_id!r} does not match enrolled host {expected_host_id!r}"
        )
    attributes = row.payload.get("attributes") or {}
    if not isinstance(attributes, dict):
        attributes = {}
    original_confidence = row.payload.get("confidence", 1.0)
    try:
        confidence = max(0.0, min(1.0, float(original_confidence)))
    except (TypeError, ValueError):
        confidence = 1.0
    severity = "informational" if row.severity in {"info", "informational", ""} else row.severity
    if severity not in {"informational", "low", "medium", "high", "critical"}:
        severity = "informational"
    response_event_id = str(
        uuid5(
            NAMESPACE_URL,
            f"quietward-response-adapter-v1:{row.host_id}:{row.event_id}",
        )
    )
    typed = _typed_sections(row.kind, row.subject, attributes)
    return {
        "schema_version": "1.0",
        "event_id": response_event_id,
        "source": "quietward",
        "source_version": "quietward-adapter-v1",
        "host_id": row.host_id,
        "host_name": row.host_id,
        "timestamp": row.observed_at,
        "event_type": row.kind,
        "category": _CATEGORY_BY_KIND.get(row.kind, "unknown"),
        "severity": severity,
        "confidence": confidence,
        "summary": f"QuietWard reported {row.kind.replace('_', ' ')} on the enrolled host.",
        "evidence": {
            "quietward_event_id": row.event_id,
            "quietward_subject": row.subject,
            "quietward_score": row.score,
            "quietward_source": row.source,
            "attributes": attributes,
            "adapter": "quietward-adapter-v1",
        },
        **typed,
        "metadata": {
            "operating_system": platform.system(),
            "quietward_adapter": True,
        },
    }


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def _headers(config: AdapterConfig, *, method: str, target: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = os.urandom(16).hex()
    signature = hmac.new(
        _derive_hmac_key(config.secret),
        _canonical_request(method, target, timestamp, nonce, body),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": config.agent_id,
        "X-QWR-Key-ID": config.key_id,
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": signature,
    }


def send_event(config: AdapterConfig, event: dict[str, Any]) -> dict[str, Any]:
    target = "/api/v1/events"
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(
        config.base_url + target,
        data=body,
        method="POST",
        headers=_headers(config, method="POST", target=target, body=body),
    )
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        if exc.code == 409:
            try:
                value = json.loads(detail)
            except json.JSONDecodeError:
                value = {}
            code = ((value.get("detail") or {}) if isinstance(value, dict) else {}).get("code")
            if code == "duplicate_event_id":
                return {"accepted": True, "duplicate": True}
        raise QuietWardAdapterError(
            f"Response API HTTP {exc.code} while sending QuietWard event: {detail}"
        ) from exc
    except (URLError, OSError) as exc:
        raise QuietWardAdapterError(f"Response API unavailable: {exc}") from exc
    if not raw:
        return {"accepted": True}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise QuietWardAdapterError("Response API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise QuietWardAdapterError("Response event endpoint returned a non-object response")
    return value


def _state_path(config: AdapterConfig) -> Path:
    return config.state_dir / "quietward-response-adapter-state.json"


def _load_checkpoint(config: AdapterConfig) -> int:
    path = _state_path(config)
    if not path.exists():
        return 0
    if path.is_symlink():
        raise QuietWardAdapterError("adapter state must not be a symbolic link")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QuietWardAdapterError("adapter state is unreadable or invalid") from exc
    if not isinstance(value, dict):
        raise QuietWardAdapterError("adapter state must be a JSON object")
    try:
        rowid = int(value.get("last_delivered_rowid", 0))
    except (TypeError, ValueError) as exc:
        raise QuietWardAdapterError("adapter checkpoint rowid is invalid") from exc
    return max(0, rowid)


def _save_checkpoint(config: AdapterConfig, row: QuietWardRow) -> None:
    path = _state_path(config)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (
        json.dumps(
            {
                "schema_version": "1.0",
                "last_delivered_rowid": row.rowid,
                "last_quietward_event_id": row.event_id,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short adapter state write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def deliver_once(config: AdapterConfig, *, limit: int = _DEFAULT_BATCH) -> int:
    checkpoint = _load_checkpoint(config)
    rows = read_rows(config.quietward_db_path, after_rowid=checkpoint, limit=limit)
    delivered = 0
    for row in rows:
        event = translate_row(row, expected_host_id=config.host_id)
        send_event(config, event)
        _save_checkpoint(config, row)
        delivered += 1
    return delivered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read QuietWard's local SQLite events read-only, translate them to the "
            "Response v1 event contract, and send them through signed agent authentication."
        )
    )
    parser.add_argument("--config", type=Path, required=True, help="Private Response-agent JSON config")
    parser.add_argument(
        "--quietward-db",
        type=Path,
        default=Path("~/.local/state/quietward/quietward.sqlite3"),
        help="QuietWard SQLite database. Opened read-only.",
    )
    parser.add_argument("--once", action="store_true", help="Deliver one bounded batch and exit")
    parser.add_argument("--batch-size", type=int, default=_DEFAULT_BATCH)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--max-backoff-seconds", type=float, default=60.0)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not 1 <= args.batch_size <= _MAX_BATCH:
        raise SystemExit(f"--batch-size must be between 1 and {_MAX_BATCH}")
    if not 1 <= args.interval_seconds <= 300:
        raise SystemExit("--interval-seconds must be between 1 and 300")
    if args.max_backoff_seconds < args.interval_seconds or args.max_backoff_seconds > 900:
        raise SystemExit("--max-backoff-seconds must be at least the interval and no more than 900")
    config = AdapterConfig.from_agent_config(
        args.config.expanduser(),
        quietward_db_path=args.quietward_db.expanduser(),
    )

    if args.once:
        print(json.dumps({"events_delivered": deliver_once(config, limit=args.batch_size)}, sort_keys=True))
        return 0

    stop = threading.Event()

    def request_stop(*_args: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    backoff = float(args.interval_seconds)
    while not stop.is_set():
        try:
            delivered = deliver_once(config, limit=args.batch_size)
            if delivered:
                print(json.dumps({"events_delivered": delivered}, sort_keys=True), flush=True)
            backoff = float(args.interval_seconds)
            stop.wait(float(args.interval_seconds))
        except QuietWardAdapterError as exc:
            detail = " ".join(str(exc).replace("\x00", "").split())[:1000]
            print(
                json.dumps(
                    {"status": "degraded", "error": detail, "retry_in_seconds": backoff},
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
            stop.wait(backoff)
            backoff = min(float(args.max_backoff_seconds), max(backoff * 2, args.interval_seconds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
