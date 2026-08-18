from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import ActionRecord, ApprovalRecord
from app.services.audit_service import record_audit


def _cancel_dispatching(
    session: Session,
    action: ActionRecord,
    *,
    reason: str,
    actor_id: str,
) -> bool:
    """Cancel a dispatch that has not yet produced an endpoint executing result.

    `dispatching` means Response returned the action from a poll, so this is a
    best-effort revocation boundary rather than a claim that the endpoint never saw
    the action. Once the endpoint has reported `executing`, recovery is preserved.
    """
    if action.status != "dispatching":
        return False
    action.status = "cancelled"
    action.policy_allowed = False
    action.policy_reasons = [reason]
    if action.approval_id:
        approval = session.get(ApprovalRecord, action.approval_id)
        if approval is not None and approval.status == "approved":
            approval.status = "cancelled"
    record_audit(
        session,
        actor_type="system",
        actor_id=actor_id,
        action="response_action_cancelled",
        resource_type="action",
        resource_id=action.action_id,
        incident_id=action.incident_id,
        details={"reason": reason, "previous_status": "dispatching"},
    )
    return True


def cancel_dispatching_actions_for_incident(
    session: Session,
    incident_id: str,
    *,
    reason: str,
) -> int:
    actions = list(
        session.scalars(
            select(ActionRecord).where(
                ActionRecord.incident_id == incident_id,
                ActionRecord.status == "dispatching",
            )
        )
    )
    cancelled = sum(
        int(_cancel_dispatching(session, action, reason=reason, actor_id="incident-state"))
        for action in actions
    )
    session.flush()
    return cancelled


def cancel_dispatching_actions_for_agent(
    session: Session,
    agent_id: str,
    *,
    reason: str = "target agent is disabled",
) -> int:
    actions = list(
        session.scalars(
            select(ActionRecord).where(
                ActionRecord.target_agent_id == agent_id,
                ActionRecord.status == "dispatching",
            )
        )
    )
    cancelled = sum(
        int(_cancel_dispatching(session, action, reason=reason, actor_id="agent-revocation"))
        for action in actions
    )
    session.flush()
    return cancelled
