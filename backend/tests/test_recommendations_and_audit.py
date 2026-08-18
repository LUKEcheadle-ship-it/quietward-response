def test_rule_based_recommendations_separate_diagnostics_and_remediation(client, event_factory) -> None:
    response = client.post(
        "/api/v1/events",
        json=event_factory(0, event_type="new_listener_detected", category="network", severity="high", network={"bind_address": "0.0.0.0", "port": 8443}),
    )
    incident = client.get(f"/api/v1/incidents/{response.json()['incident_id']}").json()
    diagnostics = [item for item in incident["recommended_actions"] if item["action_type"] == "diagnostic"]
    remediation = [item for item in incident["recommended_actions"] if item["action_type"] == "remediation"]
    assert diagnostics and all(item["enabled"] for item in diagnostics)
    assert remediation and all(not item["enabled"] for item in remediation)
    assert all(item["phase"] == "Phase 2 — not enabled" for item in remediation)


def test_audit_trail_records_pipeline_and_analyst_changes(client, event_factory) -> None:
    created = client.post(
        "/api/v1/events",
        json=event_factory(0, category="operational", event_type="disk_usage_rising"),
    ).json()
    incident_id = created["incident_id"]
    patched = client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "investigating", "severity": "high"},
        headers={"X-Actor-ID": "analyst-test"},
    )
    assert patched.status_code == 200
    actions = {entry["action"] for entry in patched.json()["audit_trail"]}
    assert {
        "incident_created",
        "recommendation_generated",
        "incident_status_changed",
        "severity_changed",
    }.issubset(actions)
    assert all(entry["actor_id"] for entry in patched.json()["audit_trail"])
