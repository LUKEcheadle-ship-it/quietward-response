def test_event_persists_and_identical_duplicate_is_rejected_as_idempotent_retry(client, event_factory) -> None:
    event = event_factory()
    first = client.post("/api/v1/events", json=event)
    second = client.post("/api/v1/events", json=event)
    assert first.status_code == 201
    assert first.json()["accepted"] is True
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "duplicate_event_id"
    events = client.get("/api/v1/events").json()
    assert len(events) == 1
    assert events[0]["event_id"] == event["event_id"]


def test_same_event_id_with_different_payload_fails_as_conflict(client, event_factory) -> None:
    event = event_factory()
    assert client.post("/api/v1/events", json=event).status_code == 201

    conflicting = dict(event)
    conflicting["summary"] = "Different content reusing the same event ID"
    response = client.post("/api/v1/events", json=conflicting)

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "event_id_conflict"
    stored = client.get("/api/v1/events").json()
    assert len(stored) == 1
    assert stored[0]["summary"] == event["summary"]


def test_host_is_created_and_updated(client, event_factory) -> None:
    first = event_factory(0, host_id="host-update")
    second = event_factory(30, host_id="host-update", event_type="service_observed")
    second["host_name"] = "renamed-host.example.test"
    assert client.post("/api/v1/events", json=first).status_code == 201
    assert client.post("/api/v1/events", json=second).status_code == 201
    host = client.get("/api/v1/hosts/host-update").json()
    assert host["hostname"] == "renamed-host.example.test"
    assert host["event_count"] == 2
    assert host["incident_count"] == 1


def test_host_seen_bounds_handle_out_of_order_events(client, event_factory) -> None:
    later = event_factory(30, host_id="host-order", event_type="later_event")
    earlier = event_factory(0, host_id="host-order", event_type="earlier_event")
    assert client.post("/api/v1/events", json=later).status_code == 201
    assert client.post("/api/v1/events", json=earlier).status_code == 201
    host = client.get("/api/v1/hosts/host-order").json()
    assert host["first_seen"].startswith("2026-08-18T12:00:00")
    assert host["last_seen"].startswith("2026-08-18T12:00:30")


def test_event_filters(client, event_factory) -> None:
    client.post("/api/v1/events", json=event_factory(0, host_id="host-one", severity="high"))
    client.post("/api/v1/events", json=event_factory(1, host_id="host-two", severity="low"))
    assert len(client.get("/api/v1/events?host=host-one").json()) == 1
    assert len(client.get("/api/v1/events?severity=low").json()) == 1
    assert len(client.get("/api/v1/events?event_type=process_observed").json()) == 2
