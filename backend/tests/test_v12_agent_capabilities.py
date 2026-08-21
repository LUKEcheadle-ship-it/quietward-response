from __future__ import annotations

import json
import secrets
import time

from app.services.agent_auth import sign_request
from app.services.policy_service import (
    AGENT_CAPABILITY_DISABLED_REASON,
    AGENT_CAPABILITY_MISSING_REASON,
)


def _enroll(client, host_id: str = "host-capability") -> dict:
    response = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={
            "host_id": host_id,
            "display_name": "Capability test agent",
            "agent_version": "1.2.0-alpha.1",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _report(client, enrollment: dict, *, enabled: list[str], supported: list[str] | None = None, nonce: str | None = None):
    supported = supported if supported is not None else [
        "restart_quietward_demo_service",
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "terminate_process_by_handle",
        "collect_file_diagnostic",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
    ]
    payload = {
        "schema_version": "1.0",
        "agent_version": "1.2.0-alpha.1",
        "supported_actions": supported,
        "enabled_actions": enabled,
        "resource_handle_protocol": "qwrh1",
        "arbitrary_command_execution": False,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    target = f"/api/v1/agents/{enrollment['agent_id']}/capabilities"
    timestamp = str(int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    signature = sign_request(
        enrollment["secret"],
        method="POST",
        target=target,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return client.post(
        target,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-QWR-Agent-ID": enrollment["agent_id"],
            "X-QWR-Key-ID": enrollment["key_id"],
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        },
    )


def _request_process_action(client, incident_id: str, enrollment: dict) -> dict:
    response = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "capability-test"},
        json={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": enrollment["host_id"],
            "action_type": "terminate_process_by_handle",
            "parameters": {"resource_handle": "qwrh1_1234567890abcdef"},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _approve(client, action_id: str) -> dict:
    response = client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers={"X-Actor-ID": "capability-test"},
        json={"reason": "capability policy test"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_signed_capability_report_is_persisted_and_replay_protected(client) -> None:
    enrollment = _enroll(client)
    nonce = secrets.token_hex(16)
    response = _report(
        client,
        enrollment,
        enabled=[
            "restart_quietward_demo_service",
            "collect_host_diagnostic",
            "collect_process_diagnostic",
            "collect_file_diagnostic",
        ],
        nonce=nonce,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["capabilities_updated_at"] is not None
    assert body["enabled_actions"] == sorted(body["enabled_actions"])
    assert "terminate_process_by_handle" not in body["enabled_actions"]

    replay = _report(
        client,
        enrollment,
        enabled=[
            "restart_quietward_demo_service",
            "collect_host_diagnostic",
            "collect_process_diagnostic",
            "collect_file_diagnostic",
        ],
        nonce=nonce,
    )
    assert replay.status_code == 401
    assert replay.json()["detail"]["code"] == "replayed_nonce"


def test_unknown_or_command_capability_is_rejected(client) -> None:
    enrollment = _enroll(client, "host-capability-unknown")
    response = _report(
        client,
        enrollment,
        enabled=[],
        supported=["collect_host_diagnostic", "run_shell"],
    )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "unknown_agent_capability"
    assert response.json()["detail"]["actions"] == ["run_shell"]


def test_policy_requires_agent_to_sign_and_enable_high_impact_capability(client, event_factory) -> None:
    host_id = "host-capability-policy"
    event = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="privilege_escalation",
            category="privilege",
            severity="high",
            metadata={"operating_system": "Linux"},
        ),
    )
    assert event.status_code == 201, event.text
    incident_id = event.json()["incident_id"]
    enrollment = _enroll(client, host_id)

    missing = _approve(client, _request_process_action(client, incident_id, enrollment)["action_id"])
    assert missing["status"] == "cancelled"
    assert missing["policy_allowed"] is False
    assert AGENT_CAPABILITY_MISSING_REASON in missing["policy_reasons"]

    report = _report(
        client,
        enrollment,
        enabled=[
            "restart_quietward_demo_service",
            "collect_host_diagnostic",
            "collect_process_diagnostic",
            "collect_file_diagnostic",
        ],
    )
    assert report.status_code == 200, report.text

    disabled = _approve(client, _request_process_action(client, incident_id, enrollment)["action_id"])
    assert disabled["status"] == "cancelled"
    assert disabled["policy_allowed"] is False
    assert AGENT_CAPABILITY_DISABLED_REASON in disabled["policy_reasons"]

    enabled = list(report.json()["enabled_actions"]) + ["terminate_process_by_handle"]
    enabled_report = _report(client, enrollment, enabled=enabled)
    assert enabled_report.status_code == 200, enabled_report.text

    allowed = _approve(client, _request_process_action(client, incident_id, enrollment)["action_id"])
    assert allowed["status"] == "approved"
    assert allowed["policy_allowed"] is True
    assert allowed["policy_reasons"] == []
