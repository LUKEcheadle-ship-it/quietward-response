from datetime import datetime

from app.database.session import SessionLocal
from app.models.audit import Audit
from app.models.event import Event
from app.services.incident_service import recommendations_for
from app.services.timeline import build_timeline


def test_host_is_created_then_updated(client, event_factory):
    first = event_factory()
    second = event_factory(event_id="f970b234-b5c1-41ec-b96b-f6af66cba91e", timestamp="2026-08-17T21:42:03Z", host_name="alpha-renamed", source_version="1.0.0")
    client.post("/api/v1/events", json=first)
    client.post("/api/v1/events", json=second)
    host = client.get("/api/v1/hosts/host-alpha").json()
    assert host["hostname"] == "alpha-renamed"
    assert host["agent_version"] == "1.0.0"
    assert len(client.get("/api/v1/hosts").json()) == 1


def test_related_events_form_one_explainable_incident(client, event_factory):
    first = client.post("/api/v1/events", json=event_factory()).json()
    second_payload = event_factory(
        event_id="69999e18-8052-4450-aec9-84479e247a71",
        timestamp="2026-08-17T21:41:11Z",
        event_type="scheduled_task.created",
        summary="Scheduled task created for unknown executable",
        persistence={"mechanism": "scheduled_task", "name": "UpdateTelemetry"},
    )
    second = client.post("/api/v1/events", json=second_payload).json()
    assert first["incident_id"] == second["incident_id"]
    assert second["incident_created"] is False
    assert "same host within 5-minute correlation window" in second["correlation_reasons"]
    detail = client.get(f"/api/v1/incidents/{first['incident_id']}").json()
    assert detail["event_count"] == 2
    assert detail["title"] == "Potential persistence activity"
    assert detail["timeline"][0]["event_id"] == first["event_id"]


def test_events_outside_window_create_separate_incidents(client, event_factory):
    first = client.post("/api/v1/events", json=event_factory()).json()
    later = client.post("/api/v1/events", json=event_factory(event_id="0232edc2-b835-4b20-a4a7-16f4136f89ad", timestamp="2026-08-17T22:00:00Z")).json()
    assert first["incident_id"] != later["incident_id"]


def test_severity_rolls_up_and_patch_is_audited(client, event_factory):
    created = client.post("/api/v1/events", json=event_factory(severity="medium")).json()
    client.post("/api/v1/events", json=event_factory(event_id="0652fd5e-bf72-4cf7-bf83-7db8ac035945", timestamp="2026-08-17T21:42:00Z", severity="critical"))
    incident_id = created["incident_id"]
    assert client.get(f"/api/v1/incidents/{incident_id}").json()["severity"] == "critical"
    patched = client.patch(f"/api/v1/incidents/{incident_id}", json={"status": "investigating"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "investigating"
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert any(item["action"] == "incident.status_changed" for item in detail["audit_trail"])


def test_timeline_is_chronological():
    later = Event(event_id="later", timestamp=datetime(2026, 1, 1, 12, 1), event_type="b", summary="later", severity="low", evidence={})
    earlier = Event(event_id="earlier", timestamp=datetime(2026, 1, 1, 12, 0), event_type="a", summary="earlier", severity="low", evidence={})
    assert [item["event_id"] for item in build_timeline([later, earlier])] == ["earlier", "later"]


def test_rule_based_recommendations_separate_diagnostics_and_disabled_remediation():
    event = Event(event_id="one", event_type="new_listener.detected", category="network", summary="Wildcard bind detected", host_id="host", host_name="host")
    actions = recommendations_for([event])
    assert any(item["type"] == "diagnostic" and item["enabled"] for item in actions)
    remediation = [item for item in actions if item["type"] == "remediation"]
    assert remediation and all(not item["enabled"] for item in remediation)
    assert all(item["note"] == "Phase 2 — not enabled" for item in remediation)


def test_audit_entries_cover_pipeline(client, event_factory):
    result = client.post("/api/v1/events", json=event_factory()).json()
    detail = client.get(f"/api/v1/incidents/{result['incident_id']}").json()
    actions = {entry["action"] for entry in detail["audit_trail"]}
    assert {"incident.created", "event.received", "event.added_to_incident", "recommendation.generated"} <= actions


def test_api_not_found_and_summary(client):
    assert client.get("/api/v1/incidents/not-real").status_code == 404
    assert client.get("/api/v1/hosts/not-real").status_code == 404
    summary = client.get("/api/v1/incidents/summary")
    assert summary.status_code == 200
    assert summary.json()["active_incidents"] == 0
