from __future__ import annotations

from datetime import datetime, timezone


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def test_incident_updated_at_advances_on_status_or_severity_change(client, event_factory) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(host_id="updated-at-host"),
    )
    assert created.status_code == 201, created.text
    incident_id = created.json()["incident_id"]

    original = client.get(f"/api/v1/incidents/{incident_id}").json()
    original_updated = _utc(original["updated_at"])

    status_change = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Actor-ID": "updated-at-test"},
        json={"status": "investigating"},
    )
    assert status_change.status_code == 200, status_change.text
    after_status = _utc(status_change.json()["updated_at"])
    assert after_status >= original_updated

    severity_change = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Actor-ID": "updated-at-test"},
        json={"severity": "high"},
    )
    assert severity_change.status_code == 200, severity_change.text
    after_severity = _utc(severity_change.json()["updated_at"])
    assert after_severity >= after_status

    # A no-op patch must not manufacture a new incident update timestamp.
    no_op = client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Actor-ID": "updated-at-test"},
        json={"severity": "high"},
    )
    assert no_op.status_code == 200, no_op.text
    assert _utc(no_op.json()["updated_at"]) == after_severity
