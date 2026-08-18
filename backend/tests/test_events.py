from app.database.session import SessionLocal
from app.models.audit import Audit
from app.models.event import Event


def test_event_validation_rejects_missing_and_unknown_fields(client, event_factory):
    payload = event_factory()
    del payload["summary"]
    payload["unexpected"] = "nope"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422
    with SessionLocal() as db:
        assert db.query(Audit).filter(Audit.action == "event.rejected").count() == 1


def test_event_validation_requires_timezone(client, event_factory):
    response = client.post("/api/v1/events", json=event_factory(timestamp="2026-08-17T21:41:03"))
    assert response.status_code == 422


def test_event_persists_and_is_listed(client, event_factory):
    payload = event_factory()
    created = client.post("/api/v1/events", json=payload)
    assert created.status_code == 201
    assert created.json()["status"] == "accepted"
    response = client.get("/api/v1/events", params={"severity": "high", "host": "host-alpha"})
    assert response.status_code == 200
    assert [event["event_id"] for event in response.json()] == [payload["event_id"]]
    with SessionLocal() as db:
        assert db.get(Event, payload["event_id"]) is not None


def test_duplicate_event_is_rejected_and_audited(client, event_factory):
    payload = event_factory()
    assert client.post("/api/v1/events", json=payload).status_code == 201
    duplicate = client.post("/api/v1/events", json=payload)
    assert duplicate.status_code == 409
    with SessionLocal() as db:
        assert db.query(Event).count() == 1
        assert db.query(Audit).filter(Audit.action == "event.rejected").count() == 1
