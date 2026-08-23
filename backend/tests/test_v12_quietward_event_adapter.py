from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path
from uuid import UUID

import pytest

from app.services.agent_auth import sign_request
from scripts.quietward_event_adapter import (
    AdapterConfig,
    QuietWardAdapterError,
    QuietWardRow,
    _headers,
    read_rows,
    translate_row,
)


def _row() -> QuietWardRow:
    return QuietWardRow(
        rowid=7,
        event_id="fse-original-123",
        observed_at="2026-08-23T20:00:00Z",
        host_id="host-alpha",
        source="windows_process_snapshot",
        kind="process_start",
        subject="powershell.exe",
        severity="high",
        score=82.0,
        payload={
            "confidence": 0.9,
            "attributes": {
                "pid": 4242,
                "ppid": 100,
                "command_name": "powershell.exe",
                "args_hash": "privacy-hash",
                "suspicious_markers": ["reverse_shell"],
                "raw_arguments_persisted": False,
            },
        },
    )


def test_adapter_translation_is_stable_versioned_and_response_compatible() -> None:
    first = translate_row(_row(), expected_host_id="host-alpha")
    second = translate_row(_row(), expected_host_id="host-alpha")

    assert first == second
    UUID(first["event_id"])
    assert first["schema_version"] == "1.0"
    assert first["source"] == "quietward"
    assert first["event_type"] == "process_start"
    assert first["category"] == "execution"
    assert first["severity"] == "high"
    assert first["process"]["pid"] == 4242
    assert first["process"]["image"] == "powershell.exe"
    assert first["evidence"]["quietward_event_id"] == "fse-original-123"
    assert first["evidence"]["attributes"]["raw_arguments_persisted"] is False


def test_adapter_refuses_cross_host_database_rows() -> None:
    with pytest.raises(QuietWardAdapterError, match="does not match enrolled host"):
        translate_row(_row(), expected_host_id="another-host")


def test_adapter_reads_quietward_database_query_only(tmp_path: Path) -> None:
    database = tmp_path / "quietward.sqlite3"
    connection = sqlite3.connect(database)
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
    payload = json.dumps(
        {
            "confidence": 1.0,
            "attributes": {"source_address_hash": "keyed-pseudonym"},
        }
    )
    connection.execute(
        "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
        (
            "fse-1",
            "2026-08-23T20:00:00Z",
            "host-alpha",
            "journald_ssh_read_only",
            "auth_failure",
            "auth:pseudonym",
            "high",
            65.0,
            payload,
        ),
    )
    connection.commit()
    connection.close()

    rows = read_rows(database, after_rowid=0, limit=10)
    assert len(rows) == 1
    assert rows[0].event_id == "fse-1"
    assert rows[0].kind == "auth_failure"

    # The adapter must not acquire write access through its read-only connection.
    direct = sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True)
    direct.execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError):
        direct.execute("DELETE FROM events")
    direct.close()


def test_adapter_hmac_matches_response_agent_auth_contract(tmp_path: Path) -> None:
    config = AdapterConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-alpha",
        key_id="key-alpha",
        secret="secret-value-for-test",
        host_id="host-alpha",
        state_dir=tmp_path,
        quietward_db_path=tmp_path / "quietward.sqlite3",
    )
    event = translate_row(_row(), expected_host_id="host-alpha")
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = _headers(config, method="POST", target="/api/v1/events", body=body)
    expected = sign_request(
        config.secret,
        method="POST",
        target="/api/v1/events",
        timestamp=headers["X-QWR-Timestamp"],
        nonce=headers["X-QWR-Nonce"],
        body=body,
    )
    assert headers["X-QWR-Signature"] == expected


def test_adapter_runtime_rejects_insecure_config_file_on_posix(tmp_path: Path) -> None:
    config_path = tmp_path / "agent.json"
    config_path.write_text(
        json.dumps(
            {
                "base_url": "http://127.0.0.1:8002",
                "agent_id": "agent-alpha",
                "key_id": "key-alpha",
                "secret": "secret-value-for-test",
                "host_id": "host-alpha",
                "state_dir": str((tmp_path / "state").resolve()),
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        config_path.chmod(0o644)
        with pytest.raises(QuietWardAdapterError, match="group/world accessible"):
            AdapterConfig.from_agent_config(
                config_path.resolve(),
                quietward_db_path=(tmp_path / "quietward.sqlite3").resolve(),
            )
        config_path.chmod(0o600)
    loaded = AdapterConfig.from_agent_config(
        config_path.resolve(),
        quietward_db_path=(tmp_path / "quietward.sqlite3").resolve(),
    )
    assert loaded.agent_id == "agent-alpha"


def test_adapter_source_has_no_response_action_or_host_execution_surface() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "quietward_event_adapter.py").read_text(encoding="utf-8")
    for forbidden in (
        "/actions/pending",
        "terminate_process",
        "quarantine_artifact",
        "restore_quarantined",
        "import subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "shell=True",
    ):
        assert forbidden not in source
    assert "mode=ro" in source
    assert '"source": "quietward"' in source
