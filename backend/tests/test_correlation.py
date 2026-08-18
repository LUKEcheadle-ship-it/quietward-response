def test_related_persistence_events_form_one_explainable_incident(client, event_factory) -> None:
    executable = "/opt/test/worker"
    payloads = [
        event_factory(0, event_type="unknown_executable_created", category="persistence", severity="high", file={"path": executable}),
        event_factory(10, event_type="scheduled_task_created", category="persistence", severity="high", file={"path": executable}, persistence={"mechanism": "scheduled_task"}),
        event_factory(20, event_type="process_launched", category="persistence", severity="high", process={"pid": 4321, "path": executable}),
        event_factory(30, event_type="outbound_connection", category="persistence", severity="critical", process={"pid": 4321, "path": executable}, network={"destination_address": "198.51.100.8"}),
    ]
    incident_ids = {
        client.post("/api/v1/events", json=payload).json()["incident_id"]
        for payload in payloads
    }
    assert len(incident_ids) == 1
    incident = client.get(f"/api/v1/incidents/{incident_ids.pop()}").json()
    assert incident["event_count"] == 4
    assert incident["severity"] == "critical"
    assert incident["affected_hosts"] == ["host-alpha"]
    assert any("shared category" in reason for reason in incident["correlation_reasons"])
    assert any("executable" in reason for reason in incident["correlation_reasons"])
    assert [entry["timestamp"] for entry in incident["timeline"]] == sorted(
        entry["timestamp"] for entry in incident["timeline"]
    )


def test_unrelated_categories_do_not_merge(client, event_factory) -> None:
    first = client.post("/api/v1/events", json=event_factory(0, category="identity"))
    second = client.post(
        "/api/v1/events",
        json=event_factory(1, event_type="disk_usage_rising", category="operational"),
    )
    assert first.json()["incident_id"] != second.json()["incident_id"]


def test_events_outside_window_do_not_merge(client, event_factory) -> None:
    first = client.post("/api/v1/events", json=event_factory(0, category="network"))
    second = client.post(
        "/api/v1/events",
        json=event_factory(601, event_type="new_listener", category="network"),
    )
    assert first.json()["incident_id"] != second.json()["incident_id"]
