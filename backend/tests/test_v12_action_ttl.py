from __future__ import annotations

from datetime import datetime, timezone

from app.database.models import AgentRecord


V12_ACTIONS = [
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
    "terminate_process_by_handle",
    "collect_file_diagnostic",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
]


def _enroll(client, host_id: str) -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"ttl-test-{host_id}",
            "agent_version": "1.2.0-alpha.1-test",
        },
    )
    assert response.status_code == 201, response.text
    enrollment = response.json()
    # This test isolates action TTL behavior. Signed capability-report transport is
    # independently exercised by test_v12_agent_capabilities.py.
    with client.app.state.database.session_factory() as session:
        agent = session.get(AgentRecord, enrollment["agent_id"])
        assert agent is not None
        agent.supported_actions = list(V12_ACTIONS)
        agent.enabled_actions = list(V12_ACTIONS)
        agent.capabilities_updated_at = datetime.now(timezone.utc)
        session.commit()
    return enrollment


def _seconds(action: dict) -> int:
    requested = datetime.fromisoformat(action["requested_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(action["expires_at"].replace("Z", "+00:00"))
    return round((expires - requested).total_seconds())


def test_handle_bound_process_action_defaults_below_resource_handle_ttl(
    client,
    event_factory,
) -> None:
    host_id = "host-handle-ttl"
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="privilege_escalation",
            category="privilege",
            severity="high",
            metadata={"operating_system": "Linux"},
        ),
    )
    assert created.status_code == 201, created.text
    enrollment = _enroll(client, host_id)

    action = client.post(
        f"/api/v1/incidents/{created.json()['incident_id']}/actions",
        headers={"X-Actor-ID": "ttl-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "terminate_process_by_handle",
            "parameters": {"resource_handle": "qwrh1_1234567890abcdef"},
        },
    )
    assert action.status_code == 201, action.text
    assert _seconds(action.json()) == 240


def test_handle_bound_action_rejects_ttl_longer_than_action_contract(
    client,
    event_factory,
) -> None:
    host_id = "host-handle-ttl-reject"
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="malware_signature",
            category="malware",
            severity="high",
        ),
    )
    assert created.status_code == 201, created.text
    enrollment = _enroll(client, host_id)

    rejected = client.post(
        f"/api/v1/incidents/{created.json()['incident_id']}/actions",
        headers={"X-Actor-ID": "ttl-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "quarantine_artifact_by_handle",
            "parameters": {"resource_handle": "qwrh1_1234567890abcdef"},
            "expires_in_seconds": 241,
        },
    )
    assert rejected.status_code == 409
    assert "maximum for quarantine_artifact_by_handle: 240 seconds" in rejected.text


def test_read_only_diagnostic_retains_longer_approval_window(client, event_factory) -> None:
    host_id = "host-diagnostic-ttl"
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="service_unavailable",
            category="operational",
            severity="medium",
        ),
    )
    assert created.status_code == 201, created.text
    enrollment = _enroll(client, host_id)

    action = client.post(
        f"/api/v1/incidents/{created.json()['incident_id']}/actions",
        headers={"X-Actor-ID": "ttl-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_host_diagnostic",
            "parameters": {},
        },
    )
    assert action.status_code == 201, action.text
    assert _seconds(action.json()) == 600


def test_network_diagnostic_uses_bounded_read_only_approval_window(client, event_factory) -> None:
    host_id = "host-network-diagnostic-ttl"
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="outbound_connection",
            category="network",
            severity="high",
            metadata={"operating_system": "Linux"},
        ),
    )
    assert created.status_code == 201, created.text
    enrollment = _enroll(client, host_id)
    action = client.post(
        f"/api/v1/incidents/{created.json()['incident_id']}/actions",
        headers={"X-Actor-ID": "ttl-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": "collect_network_diagnostic",
            "parameters": {},
        },
    )
    assert action.status_code == 201, action.text
    assert _seconds(action.json()) == 600
