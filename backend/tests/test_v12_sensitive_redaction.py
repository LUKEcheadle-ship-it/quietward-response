from __future__ import annotations

from datetime import datetime, timezone

from app.database.models import EventRecord
from app.schemas.action import ActionResultCreate
from app.services.redaction import REDACTED, redact_sensitive, redact_sensitive_text


def test_recursive_redaction_removes_credential_fields_but_preserves_identifiers() -> None:
    value = {
        "password": "hunter2",
        "nested": {
            "access_token": "access-secret",
            "client-secret": "client-secret-value",
            "key_id": "key-123",
            "token_count": 7,
            "secretary": "not-a-secret-field",
        },
        "items": [
            {"refresh_token": "refresh-secret"},
            "Authorization: Bearer abcdefghijklmnop",
        ],
    }
    redacted = redact_sensitive(value)
    assert redacted["password"] == REDACTED
    assert redacted["nested"]["access_token"] == REDACTED
    assert redacted["nested"]["client-secret"] == REDACTED
    assert redacted["nested"]["key_id"] == "key-123"
    assert redacted["nested"]["token_count"] == 7
    assert redacted["nested"]["secretary"] == "not-a-secret-field"
    assert redacted["items"][0]["refresh_token"] == REDACTED
    assert "abcdefghijklmnop" not in redacted["items"][1]


def test_text_redaction_covers_bearer_and_assignment_patterns() -> None:
    text = "Authorization: Bearer abcdefghijklmnop password=swordfish api_key='topsecret'"
    redacted = redact_sensitive_text(text)
    assert "abcdefghijklmnop" not in redacted
    assert "swordfish" not in redacted
    assert "topsecret" not in redacted
    assert redacted.count(REDACTED) >= 3


def test_event_persistence_redacts_nested_credentials_and_summary_text(client, event_factory) -> None:
    payload = event_factory(
        host_id="host-redaction",
        event_type="security_signal",
        category="security",
        summary="Adapter failed with password=swordfish and Bearer abcdefghijklmnop",
        evidence={
            "password": "hunter2",
            "nested": {"refresh_token": "refresh-secret", "key_id": "key-ok"},
        },
        metadata={
            "operating_system": "Linux",
            "client_secret": "metadata-secret",
            "token_count": 3,
        },
    )
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 201, response.text

    with client.app.state.database.session_factory() as session:
        stored = session.get(EventRecord, payload["event_id"])
        assert stored is not None
        serialized = str(stored.payload)
        normalized = str(stored.normalized)
        for secret in (
            "hunter2",
            "refresh-secret",
            "metadata-secret",
            "swordfish",
            "abcdefghijklmnop",
        ):
            assert secret not in serialized
            assert secret not in normalized
        assert stored.payload["evidence"]["password"] == REDACTED
        assert stored.payload["evidence"]["nested"]["key_id"] == "key-ok"
        assert stored.payload["metadata"]["token_count"] == 3
        assert REDACTED in stored.summary


def test_redacted_secret_change_does_not_create_durable_secret_or_conflict(client, event_factory) -> None:
    first = event_factory(
        host_id="host-redacted-duplicate",
        event_type="security_signal",
        evidence={"password": "first-secret", "stable": "same"},
    )
    created = client.post("/api/v1/events", json=first)
    assert created.status_code == 201, created.text

    retry = dict(first)
    retry["evidence"] = {"password": "second-secret", "stable": "same"}
    duplicate = client.post("/api/v1/events", json=retry)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "duplicate_event_id"

    with client.app.state.database.session_factory() as session:
        stored = session.get(EventRecord, first["event_id"])
        assert stored is not None
        text = str(stored.payload)
        assert "first-secret" not in text
        assert "second-secret" not in text


def test_action_result_schema_redacts_result_evidence_and_error_before_persistence() -> None:
    now = datetime.now(timezone.utc)
    value = ActionResultCreate(
        action_id="00000000-0000-0000-0000-000000000001",
        agent_id="agent-redaction",
        host_id="host-redaction",
        status="failed",
        started_at=now,
        completed_at=now,
        result={
            "access_token": "result-secret",
            "nested": {"api_key": "api-secret", "key_id": "safe-key-id"},
        },
        evidence={"cookie": "session-secret", "token_count": 9},
        error="request failed Authorization: Bearer abcdefghijklmnop password=swordfish",
        agent_version="1.2.0-alpha.1",
    )
    assert value.result["access_token"] == REDACTED
    assert value.result["nested"]["api_key"] == REDACTED
    assert value.result["nested"]["key_id"] == "safe-key-id"
    assert value.evidence["cookie"] == REDACTED
    assert value.evidence["token_count"] == 9
    assert "result-secret" not in str(value.result)
    assert "session-secret" not in str(value.evidence)
    assert "abcdefghijklmnop" not in str(value.error)
    assert "swordfish" not in str(value.error)
