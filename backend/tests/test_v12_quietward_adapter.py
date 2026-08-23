from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from scripts.forward_quietward_events import QuietWardEventAdapter, translate_row
from scripts.quietward_adapter_credentials import AdapterCredentialError


class FakeAgent:
    def __init__(self, tmp_path: Path, *, host_id: str = "host-test") -> None:
        self.config = SimpleNamespace(host_id=host_id, state_dir=tmp_path / "agent-state")
        self.requests: list[tuple[str, str, dict]] = []
        self.error: AdapterCredentialError | None = None

    def _request(self, method: str, target: str, payload: dict):
        self.requests.append((method, target, payload))
        if self.error is not None:
            raise self.error
        return {"accepted": True}


def _database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE events(
            event_id TEXT PRIMARY KEY,
            observed_at TEXT NOT NULL,
            host_id TEXT NOT NULL,
            source TEXT NOT NULL,
            kind TEXT NOT NULL,
            subject TEXT NOT NULL,
            severity TEXT,
            score REAL,
            payload_json TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def _insert(
    connection: sqlite3.Connection,
    *,
    event_id: str,
    host_id: str = "host-test",
    kind: str = "process_start",
    severity: str = "high",
) -> None:
    payload = {
        "event_id": event_id,
        "observed_at": "2026-08-23T20:00:00Z",
        "host_id": host_id,
        "source": "windows_process_snapshot",
        "kind": kind,
        "subject": "powershell.exe",
        "attributes": {
            "pid": 1234,
            "ppid": 100,
            "command_name": "powershell.exe",
            "args_hash": "pseudonymous-command",
            "suspicious_markers": ["reverse_shell"],
            "raw_arguments_persisted": False,
        },
        "confidence": 0.95,
    }
    connection.execute(
        """
        INSERT INTO events(
            event_id,observed_at,host_id,source,kind,subject,severity,score,payload_json
        ) VALUES(?,?,?,?,?,?,?,?,?)
        """,
        (
            event_id,
            "2026-08-23T20:00:00Z",
            host_id,
            "windows_process_snapshot",
            kind,
            "powershell.exe",
            severity,
            78.0,
            json.dumps(payload),
        ),
    )
    connection.commit()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_adapter_reads_quietward_database_without_modifying_it(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    with _database(database) as connection:
        _insert(connection, event_id="fse-original-1")
    before = _sha256(database)

    agent = FakeAgent(tmp_path)
    adapter = QuietWardEventAdapter(
        agent=agent,
        database_path=database,
        from_beginning=True,
    )
    assert adapter.forward_once() == 1
    assert _sha256(database) == before

    method, target, payload = agent.requests[0]
    assert method == "POST"
    assert target == "/api/v1/events"
    assert payload["source"] == "quietward"
    assert payload["host_id"] == "host-test"
    assert payload["severity"] == "high"
    assert payload["event_type"] == "process_start"
    assert payload["metadata"]["quietward_database_read_only"] is True
    assert payload["metadata"]["credential_scope"] == "quietward_event_ingestion_only"
    assert payload["evidence"]["quietward_event_id"] == "fse-original-1"
    assert payload["process"]["suspicious_markers"] == ["reverse_shell"]
    UUID(payload["event_id"])


def test_adapter_event_uuid_is_deterministic(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    with _database(database) as connection:
        _insert(connection, event_id="fse-repeatable")
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT rowid,* FROM events").fetchone()
        one = translate_row(row, host_id="host-test")
        two = translate_row(row, host_id="host-test")
    finally:
        connection.close()
    assert one["event_id"] == two["event_id"]


def test_default_first_run_starts_after_existing_backlog(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    with _database(database) as connection:
        _insert(connection, event_id="fse-old")

    agent = FakeAgent(tmp_path)
    adapter = QuietWardEventAdapter(agent=agent, database_path=database)
    assert adapter.forward_once() == 0
    assert agent.requests == []

    with sqlite3.connect(database) as connection:
        _insert(connection, event_id="fse-new")
    assert adapter.forward_once() == 1
    assert agent.requests[-1][2]["evidence"]["quietward_event_id"] == "fse-new"


def test_duplicate_response_is_idempotent_and_advances_cursor(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    with _database(database) as connection:
        _insert(connection, event_id="fse-duplicate")

    agent = FakeAgent(tmp_path)
    agent.error = AdapterCredentialError(
        'Response API HTTP 409 for POST /api/v1/events: {"detail":{"code":"duplicate_event_id"}}'
    )
    adapter = QuietWardEventAdapter(
        agent=agent,
        database_path=database,
        from_beginning=True,
    )
    assert adapter.forward_once() == 1
    state = json.loads(adapter.state_path.read_text(encoding="utf-8"))
    assert state["last_rowid"] == 1


def test_host_mismatch_fails_closed_without_advancing_cursor(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    with _database(database) as connection:
        _insert(connection, event_id="fse-wrong-host", host_id="other-host")

    agent = FakeAgent(tmp_path)
    adapter = QuietWardEventAdapter(
        agent=agent,
        database_path=database,
        from_beginning=True,
    )
    with pytest.raises(AdapterCredentialError, match="host does not match"):
        adapter.forward_once()
    assert not adapter.state_path.exists()
