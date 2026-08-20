from __future__ import annotations


def test_related_new_evidence_opens_new_incident_after_resolution(client, event_factory) -> None:
    first = client.post(
        "/api/v1/events",
        json=event_factory(
            index=0,
            host_id="closed-correlation-host",
            event_type="new_listener",
            category="network",
            network={"destination_address": "198.51.100.10"},
        ),
    )
    assert first.status_code == 201, first.text
    first_incident = first.json()["incident_id"]

    resolved = client.patch(
        f"/api/v1/incidents/{first_incident}",
        headers={"X-Actor-ID": "correlation-test"},
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "resolved"

    # Same host/category/indicator and still inside the normal correlation window.
    # Closed incident history remains intact; fresh evidence must be visible as a
    # new active incident rather than silently appended to the resolved one.
    second = client.post(
        "/api/v1/events",
        json=event_factory(
            index=30,
            host_id="closed-correlation-host",
            event_type="wildcard_bind_detected",
            category="network",
            network={"destination_address": "198.51.100.10"},
        ),
    )
    assert second.status_code == 201, second.text
    second_incident = second.json()["incident_id"]
    assert second_incident != first_incident

    old_detail = client.get(f"/api/v1/incidents/{first_incident}").json()
    new_detail = client.get(f"/api/v1/incidents/{second_incident}").json()
    assert old_detail["status"] == "resolved"
    assert old_detail["event_count"] == 1
    assert new_detail["status"] == "new"
    assert new_detail["event_count"] == 1
