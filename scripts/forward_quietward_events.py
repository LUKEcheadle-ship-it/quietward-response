#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import sqlite3
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5

from quietward_adapter_credentials import (
    AdapterCredential,
    AdapterCredentialError,
    EventOnlyClient,
    _atomic_private_json,
)
from reloading_adapter_client import ReloadingEventOnlyClient

ADAPTER_VERSION = "quietward-response-adapter-v1"
MAX_BATCH = 200
MAX_STATE_BYTES = 64 * 1024

_CATEGORY_BY_KIND = {
    "malware_signature": "malware",
    "yara_match": "malware",
    "container_escape_indicator": "container",
    "container_change": "container",
    "container_configuration_change": "container",
    "sensitive_file_change": "file",
    "file_change": "file",
    "executable_created": "execution",
    "privilege_escalation": "privilege",
    "auth_failure": "identity",
    "account_change": "identity",
    "new_listening_port": "network",
    "outbound_connection": "network",
    "package_vulnerability": "vulnerability",
    "configuration_weakness": "configuration",
    "process_start": "execution",
    "persistence_change": "persistence",
    "self_integrity_change": "integrity",
    "evidence_integrity_failure": "integrity",
    "collector_health": "operational",
}


class AdapterClient(Protocol):
    config: AdapterCredential

    def _request(self, method: str, target: str, payload: dict[str, Any]) -> Any: ...


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_private_json(path, value, force=True)


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink():
        raise AdapterCredentialError("QuietWard adapter state must not be a symbolic link")
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise AdapterCredentialError("QuietWard adapter state is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES:
        raise AdapterCredentialError("QuietWard adapter state is invalid")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise AdapterCredentialError("QuietWard adapter state must not be group/world accessible")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterCredentialError("QuietWard adapter state is unreadable or invalid") from exc
    if not isinstance(value, dict):
        raise AdapterCredentialError("QuietWard adapter state must be a JSON object")
    return value


def _readonly_database(path: Path) -> sqlite3.Connection:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise AdapterCredentialError("QuietWard database path must be absolute")
    if resolved.is_symlink() or not resolved.is_file():
        raise AdapterCredentialError("QuietWard database must be a normal existing file")
    uri = "file:" + quote(resolved.as_posix(), safe="/") + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise AdapterCredentialError("QuietWard database could not be opened read-only") from exc
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _max_rowid(connection: sqlite3.Connection) -> int:
    try:
        row = connection.execute("SELECT COALESCE(MAX(rowid), 0) AS value FROM events").fetchone()
    except sqlite3.Error as exc:
        raise AdapterCredentialError("QuietWard database does not expose the expected events table") from exc
    return int(row["value"] if row is not None else 0)


def _validate_database_host(connection: sqlite3.Connection, expected_host_id: str) -> None:
    try:
        rows = list(connection.execute("SELECT DISTINCT host_id FROM events LIMIT 3"))
    except sqlite3.Error as exc:
        raise AdapterCredentialError("QuietWard database does not expose the expected events table") from exc
    hosts = {str(row["host_id"]) for row in rows if row["host_id"] not in (None, "")}
    if len(hosts) > 1:
        raise AdapterCredentialError("QuietWard adapter accepts a single-host detector database only")
    if hosts and hosts != {expected_host_id}:
        raise AdapterCredentialError(
            "QuietWard database host does not match the enrolled Response agent host"
        )


def _event_rows(
    connection: sqlite3.Connection,
    *,
    after_rowid: int,
    limit: int,
) -> list[sqlite3.Row]:
    try:
        return list(
            connection.execute(
                """
                SELECT rowid,event_id,observed_at,host_id,source,kind,subject,
                       severity,score,payload_json
                FROM events
                WHERE rowid>?
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (after_rowid, limit),
            )
        )
    except sqlite3.Error as exc:
        raise AdapterCredentialError("QuietWard events schema is incompatible with the Response adapter") from exc


def _severity(value: Any) -> str:
    raw = str(value or "informational").strip().lower()
    if raw == "info":
        return "informational"
    return raw if raw in {"informational", "low", "medium", "high", "critical"} else "informational"


def _bounded(value: Any, limit: int) -> str:
    return " ".join(str(value or "").replace("\x00", "").split())[:limit]


def _typed_sections(kind: str, subject: str, attributes: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if kind == "process_start":
        result["process"] = {
            key: attributes[key]
            for key in (
                "pid",
                "ppid",
                "user_identity_hash",
                "command_name",
                "args_hash",
                "suspicious_markers",
                "privileged_context",
            )
            if key in attributes
        }
    elif kind in {"sensitive_file_change", "file_change", "executable_created"}:
        result["file"] = {
            "subject": subject[:1024],
            **{
                key: attributes[key]
                for key in (
                    "changed_fields",
                    "previous_sha256",
                    "current_sha256",
                    "exists",
                )
                if key in attributes
            },
        }
    elif kind in {"new_listening_port", "outbound_connection"}:
        result["network"] = {
            key: attributes[key]
            for key in (
                "protocol",
                "local_address",
                "port",
                "destination_hash",
                "destination_port",
                "destination_scope",
                "process_name",
                "external_bind",
                "external_destination",
            )
            if key in attributes
        }
    elif kind in {"persistence_change", "account_change"}:
        result["persistence"] = {
            "subject": subject[:1024],
            **{
                key: attributes[key]
                for key in (
                    "category",
                    "change_type",
                    "previous_fingerprint",
                    "current_fingerprint",
                    "risk_markers",
                )
                if key in attributes
            },
        }
    return result


def translate_row(row: sqlite3.Row, *, host_id: str) -> dict[str, Any]:
    row_host = str(row["host_id"])
    if row_host != host_id:
        raise AdapterCredentialError(
            "QuietWard event host does not match the enrolled Response agent host"
        )
    try:
        original = json.loads(str(row["payload_json"]))
    except json.JSONDecodeError as exc:
        raise AdapterCredentialError("QuietWard event payload is invalid JSON") from exc
    if not isinstance(original, dict):
        raise AdapterCredentialError("QuietWard event payload must be an object")

    kind = _bounded(row["kind"], 128).lower()
    subject = _bounded(row["subject"], 1024)
    attributes = original.get("attributes") or {}
    if not isinstance(attributes, dict):
        attributes = {}
    quietward_event_id = str(row["event_id"])
    response_event_id = str(
        uuid5(
            NAMESPACE_URL,
            f"quietward-response-adapter-v1:{host_id}:{quietward_event_id}",
        )
    )
    score = row["score"]
    assessment: dict[str, Any] = {"severity": _severity(row["severity"])}
    if score is not None:
        assessment["score"] = max(0.0, min(100.0, float(score)))

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": response_event_id,
        "source": "quietward",
        "source_version": ADAPTER_VERSION,
        "host_id": host_id,
        "host_name": host_id,
        "timestamp": str(row["observed_at"]),
        "event_type": kind,
        "category": _CATEGORY_BY_KIND.get(kind, "unknown"),
        "severity": assessment["severity"],
        "confidence": max(0.0, min(1.0, float(original.get("confidence", 1.0)))),
        "summary": _bounded(f"QuietWard observed {kind.replace('_', ' ')}.", 2048),
        "evidence": {
            "quietward_event_id": quietward_event_id,
            "quietward_source": _bounded(row["source"], 128),
            "quietward_subject": subject,
            "assessment": assessment,
            "attributes": attributes,
        },
        "metadata": {
            "operating_system": platform.system(),
            "adapter": ADAPTER_VERSION,
            "quietward_database_read_only": True,
            "credential_scope": "quietward_event_ingestion_only",
        },
    }
    payload.update(_typed_sections(kind, subject, attributes))
    return payload


class QuietWardEventAdapter:
    def __init__(
        self,
        *,
        agent: AdapterClient,
        database_path: Path,
        state_path: Path | None = None,
        batch_size: int = 100,
        from_beginning: bool = False,
    ) -> None:
        if not 1 <= int(batch_size) <= MAX_BATCH:
            raise AdapterCredentialError(f"adapter batch size must be between 1 and {MAX_BATCH}")
        self.agent = agent
        self.database_path = database_path.expanduser()
        self.state_path = state_path or (
            agent.config.state_dir / "quietward-response-adapter-state.json"
        )
        if not self.state_path.is_absolute():
            raise AdapterCredentialError("QuietWard adapter state path must be absolute")
        self.batch_size = int(batch_size)
        self.from_beginning = bool(from_beginning)

    def _initial_rowid(self, connection: sqlite3.Connection) -> int:
        maximum = _max_rowid(connection)
        state = _load_state(self.state_path)
        if state:
            if state.get("host_id") != self.agent.config.host_id:
                raise AdapterCredentialError("QuietWard adapter state belongs to another host")
            last_rowid = max(0, int(state.get("last_rowid") or 0))
            return 0 if last_rowid > maximum else last_rowid
        return 0 if self.from_beginning else maximum

    def _save(self, rowid: int) -> None:
        _atomic_json(
            self.state_path,
            {
                "schema_version": "1.0",
                "adapter_version": ADAPTER_VERSION,
                "host_id": self.agent.config.host_id,
                "last_rowid": int(rowid),
                "updated_at_epoch": int(time.time()),
            },
        )

    def forward_once(self) -> int:
        with _readonly_database(self.database_path) as connection:
            _validate_database_host(connection, self.agent.config.host_id)
            after = self._initial_rowid(connection)
            rows = _event_rows(connection, after_rowid=after, limit=self.batch_size)
        if not rows:
            if not self.state_path.exists():
                self._save(after)
            return 0

        delivered = 0
        for row in rows:
            payload = translate_row(row, host_id=self.agent.config.host_id)
            try:
                self.agent._request("POST", "/api/v1/events", payload)
            except AdapterCredentialError as exc:
                text = str(exc)
                if "HTTP 409" not in text or "duplicate_event_id" not in text:
                    raise
            self._save(int(row["rowid"]))
            delivered += 1
        return delivered


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read QuietWard events from local SQLite in read-only mode and forward "
            "them as signed QuietWard Response events using an event-only credential."
        )
    )
    parser.add_argument("--config", type=Path, required=True, help="Private adapter.json event-only credential")
    parser.add_argument("--quietward-db", type=Path, required=True)
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--max-backoff-seconds", type=float, default=60.0)
    parser.add_argument("--from-beginning", action="store_true")
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.interval_seconds < 1 or args.interval_seconds > 300:
        raise SystemExit("--interval-seconds must be between 1 and 300")
    if args.max_backoff_seconds < args.interval_seconds or args.max_backoff_seconds > 900:
        raise SystemExit("--max-backoff-seconds is invalid")

    if args.once:
        config = AdapterCredential.from_file(args.config.expanduser())
        adapter = QuietWardEventAdapter(
            agent=EventOnlyClient(config),
            database_path=args.quietward_db,
            state_path=args.state_file.expanduser() if args.state_file else None,
            batch_size=args.batch_size,
            from_beginning=args.from_beginning,
        )
        print(json.dumps({"events_forwarded": adapter.forward_once()}, sort_keys=True))
        return 0

    # Continuous operation reloads adapter.json before every request. Endpoint-key
    # rotation can therefore regenerate the event subkey without restarting the
    # bridge or exposing agent.json to the adapter process.
    client = ReloadingEventOnlyClient(args.config.expanduser())
    adapter = QuietWardEventAdapter(
        agent=client,
        database_path=args.quietward_db,
        state_path=args.state_file.expanduser() if args.state_file else None,
        batch_size=args.batch_size,
        from_beginning=args.from_beginning,
    )

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    backoff = float(args.interval_seconds)
    while not stop.is_set():
        try:
            forwarded = adapter.forward_once()
            if forwarded:
                print(json.dumps({"events_forwarded": forwarded}, sort_keys=True), flush=True)
            backoff = float(args.interval_seconds)
            stop.wait(float(args.interval_seconds))
        except AdapterCredentialError as exc:
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
