from app.database.models import AuditRecord


def test_strict_event_validation_and_rejection_audit(client, event_factory) -> None:
    event = event_factory()
    del event["summary"]
    event["unexpected_top_level"] = "rejected"
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 422
    with client.app.state.database.session_factory() as session:
        audits = session.query(AuditRecord).all()
        assert len(audits) == 1
        assert audits[0].action == "event_rejected"
        assert audits[0].details["reason"] == "schema_validation_failed"


def test_timestamp_requires_timezone(client, event_factory) -> None:
    event = event_factory()
    event["timestamp"] = "2026-08-18T12:00:00"
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 422


def test_unsupported_schema_version_fails_closed(client, event_factory) -> None:
    event = event_factory()
    event["schema_version"] = "2.0"
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 422
