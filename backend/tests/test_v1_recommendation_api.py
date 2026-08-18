from __future__ import annotations


def test_controlled_recommendation_metadata_survives_incident_api(client, event_factory) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id="demo-host",
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert created.status_code == 201, created.text

    incident = client.get(f"/api/v1/incidents/{created.json()['incident_id']}")
    assert incident.status_code == 200, incident.text
    recommendations = incident.json()["recommended_actions"]
    controlled = [
        item
        for item in recommendations
        if item.get("registry_action_type") == "restart_quietward_demo_service"
    ]
    assert len(controlled) == 1
    assert controlled[0]["enabled"] is True
    assert controlled[0]["requires_approval"] is True

    # The demo fixture is transported as an operational event, but it is not a
    # disk/resource incident. Its response card should stay focused on the fixture.
    titles = {item["title"] for item in recommendations}
    assert titles == {"Confirm demo service health", "Restart QuietWard demo service"}
