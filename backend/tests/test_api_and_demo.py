from scripts.seed_demo import build_demo_events


def test_health_and_empty_overview(client) -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "service": "quietward-response",
        "version": "1.0.0rc1",
        "database": "ok",
        "remediation_enabled": False,
        "controlled_response_enabled": True,
        "controlled_action_count": 1,
        "response_scope": "demo_fixture_only",
        "single_worker_required": True,
    }
    overview = client.get("/api/v1/overview").json()
    assert overview["active_incidents"] == 0
    assert overview["remediation_enabled"] is False


def test_openapi_exposes_only_typed_controlled_action_surface(client) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    assert all(
        forbidden not in path.lower()
        for path in paths
        for forbidden in ("shell", "command", "isolate", "quarantine")
    )
    assert set(paths["/api/v1/events"]) == {"get", "post"}
    assert set(paths["/api/v1/incidents/{incident_id}"]) == {"get", "patch"}
    assert "/api/v1/actions/registry" in paths
    assert "/api/v1/incidents/{incident_id}/actions" in paths
    registry = client.get("/api/v1/actions/registry")
    assert registry.status_code == 200
    assert [item["action_type"] for item in registry.json()] == [
        "restart_quietward_demo_service"
    ]


def test_all_demo_scenarios_exercise_complete_pipeline(client) -> None:
    events = build_demo_events(batch_id="pytest-demo")
    results = [client.post("/api/v1/events", json=event) for event in events]
    assert all(response.status_code == 201 for response in results)
    incidents = client.get("/api/v1/incidents").json()
    assert len(incidents) == 3
    assert sorted(item["event_count"] for item in incidents) == [3, 3, 4]
    for incident in incidents:
        detail = client.get(f"/api/v1/incidents/{incident['incident_id']}").json()
        assert detail["timeline"]
        assert detail["probable_cause"] != "Assessment pending"
        assert detail["recommended_actions"]
        assert detail["audit_trail"]
    overview = client.get("/api/v1/overview").json()
    assert overview["hosts_reporting"] == 3
    assert overview["events_last_24h"] == 10
