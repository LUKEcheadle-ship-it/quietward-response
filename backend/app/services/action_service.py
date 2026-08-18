from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import ActionRecord, AgentRecord, ApprovalRecord, IncidentRecord
from app.schemas.action import ActionCreate, ActionResultCreate
from app.services.action_registry import get_action_definition
from app.services.audit_service import record_audit
from app.services.policy_service import evaluate_action_policy


class ActionError(ValueError):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def action_to_dict(action: ActionRecord) -> dict[str, Any]:
    return {
        "schema_version": action.schema_version,
        "action_id": action.action_id,
        "incident_id": action.incident_id,
        "target_agent_id": action.target_agent_id,
        "target_host_id": action.target_host_id,
        "action_type": action.action_type,
        "parameters": action.parameters or {},
        "requested_at": action.requested_at,
        "requested_by": action.requested_by,
        "approval_id": action.approval_id,
        "expires_at": action.expires_at,
        "status": action.status,
        "policy_allowed": action.policy_allowed,
        "policy_reasons": action.policy_reasons or [],
        "dispatched_at": action.dispatched_at,
        "started_at": action.started_at,
        "completed_at": action.completed_at,
        "result": action.result,
        "error": action.error,
        "evidence": action.evidence,
    }


def create_action(
    session: Session,
    *,
    incident_id: str,
    payload: ActionCreate,
    actor_id: str,
) -> ActionRecord:
    incident = session.get(IncidentRecord, incident_id)
    if incident is None:
        raise ActionError("incident does not exist")
    if payload.target_host_id not in (incident.affected_hosts or []):
        raise ActionError("target host is not affected by incident")
    agent = session.get(AgentRecord, payload.target_agent_id)
    if agent is None or not agent.enabled:
        raise ActionError("target agent does not exist or is disabled")
    if agent.host_id != payload.target_host_id:
        raise ActionError("target agent is not enrolled for target host")
    definition = get_action_definition(payload.action_type)
    if definition is None:
        raise ActionError("unsupported action type")
    parameter_errors = definition.validate_parameters(payload.parameters)
    if parameter_errors:
        raise ActionError("; ".join(parameter_errors))

    now = _utcnow()
    action = ActionRecord(
        incident_id=incident_id,
        target_agent_id=payload.target_agent_id,
        target_host_id=payload.target_host_id,
        action_type=payload.action_type,
        parameters=payload.parameters,
        requested_at=now,
        requested_by=actor_id,
        expires_at=now + timedelta(seconds=payload.expires_in_seconds),
        status="pending",
    )
    session.add(action)
    session.flush()
    approval = ApprovalRecord(
        incident_id=incident_id,
        action_id=action.action_id,
        requested_by=actor_id,
        requested_at=now,
        status="pending",
        expires_at=action.expires_at,
    )
    session.add(approval)
    session.flush()
    action.approval_id = approval.approval_id
    record_audit(
        session,
        actor_type="analyst",
        actor_id=actor_id,
        action="response_action_requested",
        resource_type="action",
        resource_id=action.action_id,
        incident_id=incident_id,
        details={
            "action_type": action.action_type,
            "target_agent_id": action.target_agent_id,
            "target_host_id": action.target_host_id,
            "approval_id": approval.approval_id,
        },
    )
    session.flush()
    return action


def decide_action(
    session: Session,
    *,
    action_id: str,
    actor_id: str,
    approve: bool,
    reason: str | None = None,
) -> ActionRecord:
    action = session.get(ActionRecord, action_id)
    if action is None:
        raise ActionError("action does not exist")
    if action.status not in {"pending", "approved"}:
        raise ActionError(f"action cannot be decided from status {action.status}")
    approval = session.get(ApprovalRecord, action.approval_id) if action.approval_id else None
    if approval is None:
        raise ActionError("approval record is missing")
    now = _utcnow()
    if _as_utc(approval.expires_at) <= now:
        approval.status = "expired"
        action.status = "expired"
        raise ActionError("approval has expired")

    if approve:
        approval.status = "approved"
        approval.approved_by = actor_id
        approval.approved_at = now
        action.status = "approved"
    else:
        approval.status = "rejected"
        approval.rejection_reason = reason
        action.status = "rejected"

    record_audit(
        session,
        actor_type="analyst",
        actor_id=actor_id,
        action="response_action_approved" if approve else "response_action_rejected",
        resource_type="action",
        resource_id=action.action_id,
        incident_id=action.incident_id,
        details={"approval_id": approval.approval_id, "reason": reason},
    )

    if approve:
        allowed, reasons = evaluate_action_policy(session, action, now=now)
        action.policy_allowed = allowed
        action.policy_reasons = reasons
        record_audit(
            session,
            actor_type="policy_engine",
            actor_id="deterministic-v1",
            action="action_policy_evaluated",
            resource_type="action",
            resource_id=action.action_id,
            incident_id=action.incident_id,
            details={"allowed": allowed, "reasons": reasons},
        )
    session.flush()
    return action


def list_incident_actions(session: Session, incident_id: str) -> list[ActionRecord]:
    return list(
        session.scalars(
            select(ActionRecord)
            .where(ActionRecord.incident_id == incident_id)
            .order_by(ActionRecord.requested_at.desc())
        )
    )


def pending_actions_for_agent(session: Session, agent: AgentRecord) -> list[ActionRecord]:
    now = _utcnow()
    actions = list(
        session.scalars(
            select(ActionRecord)
            .where(
                ActionRecord.target_agent_id == agent.agent_id,
                ActionRecord.status.in_(["approved", "dispatching"]),
            )
            .order_by(ActionRecord.requested_at.asc())
        )
    )
    deliverable: list[ActionRecord] = []
    for action in actions:
        if _as_utc(action.expires_at) <= now:
            action.status = "expired"
            record_audit(
                session,
                actor_type="system",
                actor_id="action-dispatch",
                action="response_action_expired",
                resource_type="action",
                resource_id=action.action_id,
                incident_id=action.incident_id,
            )
            continue
        allowed, reasons = evaluate_action_policy(session, action, now=now)
        action.policy_allowed = allowed
        action.policy_reasons = reasons
        if not allowed:
            continue
        if action.status == "approved":
            action.status = "dispatching"
            action.dispatched_at = now
            record_audit(
                session,
                actor_type="system",
                actor_id="action-dispatch",
                action="response_action_dispatched",
                resource_type="action",
                resource_id=action.action_id,
                incident_id=action.incident_id,
                details={"target_agent_id": agent.agent_id},
            )
        deliverable.append(action)
    session.flush()
    return deliverable


def apply_action_result(
    session: Session,
    *,
    agent: AgentRecord,
    payload: ActionResultCreate,
) -> ActionRecord:
    action = session.get(ActionRecord, payload.action_id)
    if action is None:
        raise ActionError("action does not exist")
    if action.target_agent_id != agent.agent_id or payload.agent_id != agent.agent_id:
        raise ActionError("result agent does not match action target")
    if action.target_host_id != payload.host_id or agent.host_id != payload.host_id:
        raise ActionError("result host does not match action target")

    if action.status in {"succeeded", "failed"}:
        if action.status == payload.status:
            return action
        raise ActionError("completed action cannot change terminal status")
    if action.status not in {"dispatching", "executing"}:
        raise ActionError(f"result is not valid from action status {action.status}")

    action.status = payload.status
    if payload.started_at is not None:
        action.started_at = payload.started_at
    elif payload.status == "executing" and action.started_at is None:
        action.started_at = _utcnow()
    if payload.status in {"succeeded", "failed"}:
        action.completed_at = payload.completed_at or _utcnow()
    action.result = payload.result
    action.error = payload.error
    action.evidence = payload.evidence

    record_audit(
        session,
        actor_type="agent",
        actor_id=agent.agent_id,
        action="response_action_result",
        resource_type="action",
        resource_id=action.action_id,
        incident_id=action.incident_id,
        details={
            "status": payload.status,
            "agent_version": payload.agent_version,
            "error": payload.error,
        },
    )
    session.flush()
    return action
