from __future__ import annotations

from sqlalchemy import select

from app.database.models import AuditRecord, EventRecord
from scripts.audit_sensitive_persistence import scan_session


def test_sensitive_persistence_audit_detects_simulated_leak_in_valid_product_rows(
    client,
    event_factory,
) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id="host-sensitive-audit-e2e",
            event_type="operational_signal",
            category="operational",
            summary="safe event before simulated persistence bug",
            evidence={"safe": True},
        ),
    )
    assert created.status_code == 201, created.text
    event_id = created.json()["event_id"]

    with client.app.state.database.session_factory() as session:
        event = session.get(EventRecord, event_id)
        assert event is not None
        # Simulate a future caller bypassing the normal ingestion redactor after
        # persistence so the audit can be tested against a structurally valid row.
        event.payload = {**(event.payload or {}), "access_token": "simulated-event-secret"}
        audit = session.scalars(
            select(AuditRecord).order_by(AuditRecord.timestamp.desc()).limit(1)
        ).first()
        assert audit is not None
        audit.details = {**(audit.details or {}), "password": "simulated-audit-secret"}
        session.commit()

        findings = scan_session(session)
        triples = {(item.table, item.record_id, item.field) for item in findings}
        assert ("events", event_id, "payload") in triples
        assert ("audit_records", audit.audit_id, "details") in triples

        output_shape = repr(findings)
        assert "simulated-event-secret" not in output_shape
        assert "simulated-audit-secret" not in output_shape
