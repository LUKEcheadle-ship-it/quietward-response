from __future__ import annotations

import json
from pathlib import Path

from scripts.quietward_adapter_credentials import AdapterCredential, EventOnlyClient
from scripts.quietward_adapter_privacy import sanitize_quietward_event_payload


def _payload() -> dict:
    return {
        "schema_version": "1.0",
        "event_id": "11111111-1111-4111-8111-111111111111",
        "source": "quietward",
        "source_version": "quietward-response-adapter-v1",
        "host_id": "host-test",
        "host_name": "host-test",
        "timestamp": "2026-08-26T12:00:00Z",
        "event_type": "outbound_connection",
        "category": "network",
        "severity": "high",
        "confidence": 0.95,
        "summary": "QuietWard observed outbound connection.",
        "evidence": {
            "quietward_event_id": "fse-privacy-test",
            "quietward_source": "windows_connection_snapshot",
            "quietward_subject": "C:/Users/alice/secret/project.exe",
            "assessment": {"severity": "high", "score": 88.0, "private": "drop"},
            "attributes": {
                "pid": 4321,
                "command_name": "project.exe",
                "user_identity_hash": "pseudonymous-user",
                "args_hash": "pseudonymous-args",
                "destination_hash": "pseudonymous-destination",
                "destination_port": 443,
                "destination_scope": "public",
                "suspicious_markers": ["reverse_shell"],
                "raw_remote_address_persisted": False,
                "local_address": "10.0.0.44",
                "remote_address": "203.0.113.77",
                "username": "alice",
                "path": "C:/Users/alice/secret/project.exe",
                "command": "powershell -enc SECRET",
                "password": "do-not-forward",
                "future_unreviewed_field": "must-not-cross-boundary",
            },
        },
        "process": {
            "pid": 4321,
            "ppid": 100,
            "command_name": "project.exe",
            "args_hash": "pseudonymous-args",
            "suspicious_markers": ["reverse_shell"],
            "path": "C:/Users/alice/secret/project.exe",
        },
        "file": {
            "subject": "C:/Users/alice/secret/project.exe",
            "current_sha256": "a" * 64,
            "exists": True,
            "absolute_path": "C:/Users/alice/secret/project.exe",
        },
        "network": {
            "protocol": "tcp",
            "local_address": "10.0.0.44",
            "destination_hash": "pseudonymous-destination",
            "destination_port": 443,
            "destination_scope": "public",
            "process_name": "project.exe",
            "remote_address": "203.0.113.77",
        },
        "persistence": {
            "category": "scheduled_task",
            "current_fingerprint": "safe-fingerprint",
            "subject": "C:/Users/alice/AppData/secret",
            "command": "raw command text",
        },
        "metadata": {
            "operating_system": "Windows",
            "adapter": "quietward-response-adapter-v1",
            "quietward_database_read_only": True,
            "credential_scope": "quietward_event_ingestion_only",
            "machine_username": "alice",
            "private_path": "C:/Users/alice",
        },
    }


def test_sanitizer_drops_raw_and_unreviewed_detector_fields() -> None:
    original = _payload()
    sanitized = sanitize_quietward_event_payload(original)
    serialized = json.dumps(sanitized, sort_keys=True)

    for forbidden in (
        "10.0.0.44",
        "203.0.113.77",
        "C:/Users/alice",
        "do-not-forward",
        "must-not-cross-boundary",
        "raw command text",
        "powershell -enc SECRET",
        '"username"',
        '"quietward_subject"',
        '"local_address"',
        '"remote_address"',
    ):
        assert forbidden not in serialized

    assert sanitized["evidence"]["assessment"] == {"severity": "high", "score": 88.0}
    assert sanitized["evidence"]["attributes"]["destination_hash"] == "pseudonymous-destination"
    assert sanitized["evidence"]["attributes"]["user_identity_hash"] == "pseudonymous-user"
    assert sanitized["evidence"]["attributes"]["suspicious_markers"] == ["reverse_shell"]
    assert sanitized["process"]["pid"] == 4321
    assert sanitized["file"]["current_sha256"] == "a" * 64
    assert sanitized["network"]["destination_hash"] == "pseudonymous-destination"
    assert sanitized["persistence"]["current_fingerprint"] == "safe-fingerprint"
    assert sanitized["metadata"]["quietward_database_read_only"] is True

    # Sanitizing the transmission must not mutate the caller's local detector row.
    assert original["network"]["local_address"] == "10.0.0.44"


def test_event_only_client_signs_and_sends_only_sanitized_payload(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, bytes] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return b"{}"

    def fake_urlopen(request, timeout):
        assert timeout == 5.0
        captured["body"] = bytes(request.data or b"")
        return FakeResponse()

    monkeypatch.setattr("scripts.quietward_adapter_credentials.urlopen", fake_urlopen)
    config = AdapterCredential(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-test",
        key_id="key-test",
        host_id="host-test",
        state_dir=tmp_path.resolve(),
        event_subkey=b"x" * 32,
        timeout_seconds=5.0,
    )
    EventOnlyClient(config)._request("POST", "/api/v1/events", _payload())

    sent = json.loads(captured["body"].decode("utf-8"))
    assert sent == sanitize_quietward_event_payload(_payload())
    assert "10.0.0.44" not in captured["body"].decode("utf-8")
    assert "C:/Users/alice" not in captured["body"].decode("utf-8")
