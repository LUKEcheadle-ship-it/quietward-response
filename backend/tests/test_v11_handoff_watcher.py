from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from response_agent import AgentConfig
from watch_quietward_handoffs import HandoffWatcherError, watch_once


def _config(tmp_path: Path) -> AgentConfig:
    state = (tmp_path / "agent-state").resolve()
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-watch-1",
        key_id="key-watch-1",
        secret="s" * 32,
        host_id="watch-host",
        state_dir=state,
    )


def _document() -> dict:
    observed = datetime.now(timezone.utc).isoformat()
    return {
        "format": "quietward-response-handoff-v1",
        "generated_at": observed,
        "source_version": "0.6.0-alpha.1",
        "source_cycle_id": 7,
        "source_chain_hash": "a" * 64,
        "host_ids": ["watch-host"],
        "events": [
            {
                "schema_version": "1.0",
                "event_id": str(uuid4()),
                "source": "quietward",
                "source_version": "0.6.0-alpha.1",
                "host_id": "watch-host",
                "host_name": None,
                "timestamp": observed,
                "event_type": "quietward_network_finding",
                "category": "network",
                "severity": "high",
                "confidence": 0.9,
                "summary": "QuietWard correlated 2 evidence item(s) into a high network finding.",
                "evidence": {
                    "event_count": 2,
                    "event_kinds": ["outbound_connection"],
                    "correlation_signal_codes": ["process_network_corroboration"],
                    "subject_hmac_sha256": "b" * 32,
                    "subject_type": "network",
                },
                "process": None,
                "file": None,
                "network": None,
                "persistence": None,
                "metadata": {
                    "quietward_response_context_version": "1.0",
                    "quietward_finding_id": "qwf-watch",
                    "quietward_score": 90.0,
                    "quietward_mode": "observe_only",
                    "requires_human_approval": True,
                    "observation_only_source": True,
                    "executable_authority": False,
                    "investigation_hints": [
                        "host_health",
                        "process_inventory",
                        "network_snapshot",
                    ],
                    "operating_system": "Linux",
                },
            }
        ],
        "safety": {
            "observation_only_source": True,
            "actions_executed": 0,
            "executable_authority": False,
            "raw_finding_subjects_included": False,
            "network_request_performed": False,
        },
    }


def _write_inbox(tmp_path: Path, document: dict | None = None) -> tuple[Path, Path]:
    inbox = (tmp_path / "outbox").resolve()
    archive = (inbox / "processed").resolve()
    inbox.mkdir(parents=True, mode=0o700)
    path = inbox / "cycle-0000000007-aaaaaaaaaaaaaaaa.json"
    path.write_text(json.dumps(document or _document(), sort_keys=True), encoding="utf-8")
    return inbox, archive


def test_watcher_ingests_then_archives_without_touching_quietward_database(tmp_path: Path) -> None:
    config = _config(tmp_path)
    inbox, archive = _write_inbox(tmp_path)

    with patch("watch_quietward_handoffs._post_event", return_value="sent") as post:
        result = watch_once(config, inbox, archive, archive_files=10)

    assert result == {
        "files_processed": 1,
        "events_sent": 1,
        "duplicates": 0,
        "already_processed": 0,
        "remaining_files": 0,
    }
    post.assert_called_once()
    assert not list(inbox.glob("cycle-*.json"))
    archived = list(archive.glob("cycle-*.json"))
    assert len(archived) == 1
    ledger = json.loads((config.state_dir / "quietward-handoff-consumption-ledger.json").read_text())
    assert len(ledger) == 1
    entry = next(iter(ledger.values()))
    assert entry["source_cycle_id"] == 7
    assert entry["events_sent"] == 1


def test_watcher_accepts_response_duplicate_as_successful_consumption(tmp_path: Path) -> None:
    config = _config(tmp_path)
    inbox, archive = _write_inbox(tmp_path)
    with patch("watch_quietward_handoffs._post_event", return_value="duplicate"):
        result = watch_once(config, inbox, archive, archive_files=10)
    assert result["files_processed"] == 1
    assert result["events_sent"] == 0
    assert result["duplicates"] == 1
    assert len(list(archive.glob("cycle-*.json"))) == 1


def test_watcher_rejects_changed_file_name_after_successful_processing(tmp_path: Path) -> None:
    config = _config(tmp_path)
    inbox, archive = _write_inbox(tmp_path)
    with patch("watch_quietward_handoffs._post_event", return_value="sent"):
        watch_once(config, inbox, archive, archive_files=10)

    archived = next(archive.glob("cycle-*.json"))
    replay = inbox / archived.name
    changed = _document()
    changed["source_chain_hash"] = "c" * 64
    replay.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")
    with pytest.raises(HandoffWatcherError, match="previously processed handoff changed"):
        watch_once(config, inbox, archive, archive_files=10)


def test_watcher_rejects_cross_host_document_before_network_send(tmp_path: Path) -> None:
    config = _config(tmp_path)
    document = _document()
    document["host_ids"] = ["another-host"]
    inbox, archive = _write_inbox(tmp_path, document)
    with patch("watch_quietward_handoffs._post_event") as post:
        with pytest.raises(HandoffWatcherError, match="not bound"):
            watch_once(config, inbox, archive, archive_files=10)
    post.assert_not_called()
