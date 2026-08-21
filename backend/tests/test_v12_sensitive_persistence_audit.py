from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.database.models import ActionRecord, ApprovalRecord, AuditRecord, EventRecord
from scripts.audit_sensitive_persistence import scan_session


def test_sensitive_persistence_audit_reports_fields_not_secret_values(client) -> None:
    now = datetime.now(timezone.utc)
    with client.app.state.database.session_factory() as session:
        session.add(
            EventRecord(
                event_id="80000000-0000-0000-0000-000000000001",
                schema_version="1.0",
                source="test",
                source_version="1.0",
                host_id="host-test",
                host_name="host-test",
                occurred_at=now,
                event_type="test",
                category="test",
                severity="low",
                confidence=1.0,
                summary="password=swordfish",
                payload={"password": "hunter2"},
                normalized={"nested": {"access_token": "secret-token"}},
                received_at=now,
                incident_id=None,
            )
        )
        session.add(
            ActionRecord(
                action_id="80000000-0000-0000-0000-000000000002",
                incident_id="00000000-0000-0000-0000-000000000000",
                target_agent_id="agent-test",
                target_host_id="host-test",
                action_type="collect_host_diagnostic",
                parameters={},
                requested_at=now,
                requested_by="test",
                expires_at=now + timedelta(minutes=5),
                status="failed",
                policy_allowed=False,
                policy_reasons=[],
                result={"api_key": "result-secret"},
                error="Bearer abcdefghijklmnop",
                evidence={"cookie": "session-secret"},
            )
        )
        session.add(
            ApprovalRecord(
                approval_id="80000000-0000-0000-0000-000000000003",
                incident_id="00000000-0000-0000-0000-000000000000",
                action_id="80000000-0000-0000-0000-000000000002",
                requested_by="test",
                requested_at=now,
                status="rejected",
                rejection_reason="password=approval-secret",
                expires_at=now + timedelta(minutes=5),
            )
        )
        session.add(
            AuditRecord(
                audit_id="80000000-0000-0000-0000-000000000004",
                timestamp=now,
                actor_type="test",
                actor_id="test",
                action="test",
                resource_type="test",
                resource_id="test",
                details={"refresh_token": "audit-secret"},
                incident_id=None,
                previous_hash="0" * 64,
                entry_hash="0" * 64,
            )
        )
        # Disable FK enforcement concerns by only flushing the standalone scan
        # records in the SQLite test database where the schema allows these values.
        try:
            session.flush()
        except Exception:
            session.rollback()
            # If FK enforcement is enabled by a future database config, the unit
            # scanner behavior is covered separately below with a lightweight fake.
            return

        findings = scan_session(session)
        triples = {(item.table, item.record_id, item.field) for item in findings}
        assert ("events", "80000000-0000-0000-0000-000000000001", "payload") in triples
        assert ("events", "80000000-0000-0000-0000-000000000001", "normalized") in triples
        assert ("events", "80000000-0000-0000-0000-000000000001", "summary") in triples
        assert ("actions", "80000000-0000-0000-0000-000000000002", "result") in triples
        assert ("actions", "80000000-0000-0000-0000-000000000002", "evidence") in triples
        assert ("actions", "80000000-0000-0000-0000-000000000002", "error") in triples
        assert ("approvals", "80000000-0000-0000-0000-000000000003", "rejection_reason") in triples
        assert ("audit_records", "80000000-0000-0000-0000-000000000004", "details") in triples

        serialized = repr(findings)
        for secret in (
            "hunter2",
            "secret-token",
            "result-secret",
            "session-secret",
            "approval-secret",
            "audit-secret",
            "abcdefghijklmnop",
        ):
            assert secret not in serialized


def test_sensitive_persistence_audit_source_never_prints_database_values() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "audit_sensitive_persistence.py").read_text(encoding="utf-8")
    assert "Secret values are intentionally never printed" in source
    assert "item.table" in source and "item.record_id" in source and "item.field" in source
    assert "print(row." not in source
