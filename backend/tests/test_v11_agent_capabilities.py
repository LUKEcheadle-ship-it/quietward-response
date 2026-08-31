from __future__ import annotations

import json
import time
from uuid import uuid4

from app.database.capabilities import AgentCapabilityRecord
from app.services.agent_auth import sign_request


def _enroll(client, host_id: str = "diag-host") -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": f"Response diagnostic agent on {host_id}",
            "agent_version": "1.1.0-alpha.1",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_post(client, enrollment: dict, target: str, payload: dict):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = "cap-" + uuid4().hex
    headers = {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": enrollment["agent_id"],
        "X-QWR-Key-ID": enrollment["key_id"],
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": sign_request(
            enrollment["secret"],
            method="POST",
            target=target,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        ),
    }
    return client.post(target, content=body, headers=headers)


def _network_incident(client, event_factory, host_id: str) -> str:
    created = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="c2_beacon_detected",
            category="network",
            severity="high",
            metadata={"operating_system": "Linux"},
        ),
    )
    assert created.status_code == 201, created.text
    return created.json()["incident_id"]


def _request_and_approve(client, incident_id: str, enrollment: dict, action_type: str):
    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": enrollment["host_id"],
            "action_type": action_type,
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    approved = client.post(
        f"/api/v1/actions/{created.json()['action_id']}/approve",
        json={"reason": "diagnostic capability test"},
    )
    assert approved.status_code == 200, approved.text
    return approved.json()


def test_legacy_agent_is_demo_only_until_signed_capabilities_are_reported(
    client,
    event_factory,
) -> None:
    enrollment = _enroll(client)
    incident_id = _network_incident(client, event_factory, enrollment["host_id"])

    blocked = _request_and_approve(
        client,
        incident_id,
        enrollment,
        "collect_network_diagnostic",
    )
    assert blocked["status"] == "cancelled"
    assert blocked["policy_allowed"] is False
    assert blocked["policy_reasons"] == [
        "target agent has not enabled this signed capability"
    ]

    target = f"/api/v1/agents/{enrollment['agent_id']}/capabilities"
    capabilities = {
        "schema_version": "1.0",
        "agent_version": "1.1.0-alpha.1",
        "supported_actions": [
            "collect_host_diagnostic",
            "collect_network_diagnostic",
            "collect_process_diagnostic",
            "restart_quietward_demo_service",
        ],
        "enabled_actions": [
            "collect_host_diagnostic",
            "collect_network_diagnostic",
            "collect_process_diagnostic",
            "restart_quietward_demo_service",
        ],
        "arbitrary_command_execution": False,
    }
    reported = _signed_post(client, enrollment, target, capabilities)
    assert reported.status_code == 200, reported.text
    assert set(reported.json()["enabled_actions"]) == set(capabilities["enabled_actions"])

    allowed = _request_and_approve(
        client,
        incident_id,
        enrollment,
        "collect_network_diagnostic",
    )
    assert allowed["status"] == "approved"
    assert allowed["policy_allowed"] is True
    assert allowed["policy_reasons"] == []

    with client.app.state.database.session_factory() as session:
        record = session.get(AgentCapabilityRecord, enrollment["agent_id"])
        assert record is not None
        assert record.arbitrary_command_execution is False


def test_capability_report_cannot_enable_unknown_or_command_execution_surface(client) -> None:
    enrollment = _enroll(client, host_id="diag-host-2")
    target = f"/api/v1/agents/{enrollment['agent_id']}/capabilities"

    command_surface = _signed_post(
        client,
        enrollment,
        target,
        {
            "schema_version": "1.0",
            "agent_version": "1.1.0-alpha.1",
            "supported_actions": ["collect_host_diagnostic"],
            "enabled_actions": ["collect_host_diagnostic"],
            "arbitrary_command_execution": True,
        },
    )
    assert command_surface.status_code == 422

    unknown = _signed_post(
        client,
        enrollment,
        target,
        {
            "schema_version": "1.0",
            "agent_version": "1.1.0-alpha.1",
            "supported_actions": ["run_arbitrary_command"],
            "enabled_actions": ["run_arbitrary_command"],
            "arbitrary_command_execution": False,
        },
    )
    assert unknown.status_code == 422
    assert unknown.json()["detail"]["code"] == "unknown_agent_capability"
