from __future__ import annotations

from sqlalchemy import select

from app.database.models import ActionRecord, ApprovalRecord, AuditRecord


def test_approval_decision_is_single_shot_and_cannot_rewrite_actor(client, event_factory) -> None:
    host_id = "single-shot-approval-host"
    incident = client.post(
        "/api/v1/events",
        json=event_factory(
            host_id=host_id,
            event_type="quietward_demo_service_unhealthy",
            category="operational",
            summary="Dedicated demo fixture is unhealthy",
        ),
    )
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["incident_id"]

    enrollment = client.post(
        "/api/v1/agents/enroll",
        headers={"X-QWR-Enrollment-Token": "development-enrollment-token-change-me"},
        json={"host_id": host_id, "display_name": "single-shot-agent", "agent_version": "test"},
    )
    assert enrollment.status_code == 201, enrollment.text
    agent = enrollment.json()

    created = client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        headers={"X-Actor-ID": "requesting-analyst"},
        json={
            "target_agent_id": agent["agent_id"],
            "target_host_id": host_id,
            "action_type": "restart_quietward_demo_service",
            "parameters": {},
        },
    )
    assert created.status_code == 201, created.text
    action_id = created.json()["action_id"]

    first = client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers={"X-Actor-ID": "first-approver"},
        json={"reason": "first and only approval"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "approved"

    second = client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers={"X-Actor-ID": "second-approver"},
        json={"reason": "must not overwrite history"},
    )
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "action_decision_already_recorded"

    reject_after_approval = client.post(
        f"/api/v1/actions/{action_id}/reject",
        headers={"X-Actor-ID": "late-rejector"},
        json={"reason": "must use a separate cancellation lifecycle"},
    )
    assert reject_after_approval.status_code == 409
    assert reject_after_approval.json()["detail"]["code"] == "action_decision_already_recorded"

    with client.app.state.database.session_factory() as session:
        action = session.get(ActionRecord, action_id)
        assert action is not None and action.approval_id
        approval = session.get(ApprovalRecord, action.approval_id)
        assert approval is not None
        assert approval.status == "approved"
        assert approval.approved_by == "first-approver"
        assert approval.rejection_reason is None

        approvals = list(
            session.scalars(
                select(AuditRecord).where(
                    AuditRecord.resource_id == action_id,
                    AuditRecord.action == "response_action_approved",
                )
            )
        )
        assert len(approvals) == 1
        assert approvals[0].actor_id == "first-approver"
