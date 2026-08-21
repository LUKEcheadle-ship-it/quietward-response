from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.config import Settings
from app.database.models import AuditRecord
from app.main import create_app
from app.services.audit_service import (
    GENESIS_HASH,
    _hash_entry,
    _ordered_records,
    record_audit,
    verify_audit_chain,
)


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        environment="development",
        database_url=f"sqlite:///{(tmp_path / 'checkpoint.db').as_posix()}",
        api_host="127.0.0.1",
        cors_origins=["http://localhost:3001"],
        log_level="WARNING",
        enrollment_token="development-enrollment-token-change-me",
        audit_checkpoint_secret="test-audit-checkpoint-secret-v12-0123456789",
    )
    return TestClient(create_app(settings=settings))


def _append(client: TestClient, count: int) -> None:
    with client.app.state.database.session_factory() as session:
        for index in range(count):
            record_audit(
                session,
                actor_type="test",
                actor_id="checkpoint-test",
                action=f"test_action_{index}",
                resource_type="test",
                resource_id=f"resource-{index}",
                details={"index": index},
            )
        session.commit()


def _recompute_entire_chain(client: TestClient) -> None:
    with client.app.state.database.session_factory() as session:
        records = _ordered_records(session)
        assert records
        records[0].details = {"rewritten": True}
        previous = GENESIS_HASH
        for record in records:
            record.previous_hash = previous
            record.entry_hash = _hash_entry(
                audit_id=record.audit_id,
                timestamp=record.timestamp,
                actor_type=record.actor_type,
                actor_id=record.actor_id,
                action=record.action,
                resource_type=record.resource_type,
                resource_id=record.resource_id,
                details=record.details or {},
                incident_id=record.incident_id,
                previous_hash=previous,
            )
            previous = record.entry_hash
        session.commit()
        assert verify_audit_chain(session)["valid"] is True


def test_checkpoint_survives_legitimate_append_and_verifies_historical_prefix(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        _append(client, 3)
        checkpoint = client.get("/api/v1/audit/checkpoint")
        assert checkpoint.status_code == 200, checkpoint.text
        value = checkpoint.json()
        assert value["entries_checked"] == 3
        assert len(value["head_hash"]) == 64
        assert len(value["signature"]) == 64

        _append(client, 2)
        verified = client.post("/api/v1/audit/checkpoint/verify", json=value)
        assert verified.status_code == 200, verified.text
        result = verified.json()
        assert result["valid"] is True
        assert result["signature_valid"] is True
        assert result["prefix_valid"] is True
        assert result["current_entries"] == 5


def test_signed_checkpoint_detects_full_chain_recomputation(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        _append(client, 4)
        checkpoint = client.get("/api/v1/audit/checkpoint").json()
        _recompute_entire_chain(client)

        # A plain hash-chain verifier sees the attacker's internally consistent
        # rewrite as valid. The previously retained signed head does not.
        assert client.get("/api/v1/audit/verify").json()["valid"] is True
        result = client.post("/api/v1/audit/checkpoint/verify", json=checkpoint).json()
        assert result["valid"] is False
        assert result["signature_valid"] is True
        assert result["prefix_valid"] is False
        assert result["error"] == "checkpoint_prefix_hash_mismatch"


def test_signed_checkpoint_detects_suffix_deletion(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        _append(client, 4)
        checkpoint = client.get("/api/v1/audit/checkpoint").json()
        with client.app.state.database.session_factory() as session:
            records = _ordered_records(session)
            session.execute(delete(AuditRecord).where(AuditRecord.audit_id == records[-1].audit_id))
            session.commit()
            assert verify_audit_chain(session)["valid"] is True

        result = client.post("/api/v1/audit/checkpoint/verify", json=checkpoint).json()
        assert result["valid"] is False
        assert result["signature_valid"] is True
        assert result["prefix_valid"] is False
        assert result["error"] == "checkpoint_prefix_missing_or_truncated"


def test_checkpoint_signature_tamper_is_rejected(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        _append(client, 1)
        checkpoint = client.get("/api/v1/audit/checkpoint").json()
        replacement = "0" if checkpoint["signature"][0] != "0" else "1"
        checkpoint["signature"] = replacement + checkpoint["signature"][1:]
        result = client.post("/api/v1/audit/checkpoint/verify", json=checkpoint).json()
        assert result["valid"] is False
        assert result["signature_valid"] is False
        assert result["error"] == "checkpoint_signature_invalid"
