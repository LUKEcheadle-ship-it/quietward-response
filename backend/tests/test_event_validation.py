from app.database.models import AuditRecord, EventRecord


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


def test_quietward_info_alias_normalizes_to_informational(client, event_factory) -> None:
    event = event_factory(severity="medium")
    event["severity"] = "info"
    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 201, response.text

    with client.app.state.database.session_factory() as session:
        stored = session.get(EventRecord, event["event_id"])
        assert stored is not None
        assert stored.severity == "informational"
