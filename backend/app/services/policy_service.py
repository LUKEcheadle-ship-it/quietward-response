from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import (
    ActionRecord,
    AgentRecord,
    ApprovalRecord,
    HostRecord,
    IncidentRecord,
)
from app.services.action_registry import get_action_definition


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def evaluate_action_policy(
    session: Session,
    action: ActionRecord,
    *,
    now: datetime | None = None,
) -> tuple[bool, list[str]]:
    now = now or datetime.now(timezone.utc)
    reasons: list[str] = []

    definition = get_action_definition(action.action_type)
    if definition is None:
        reasons.append("action type is not registered")
        return False, reasons

    parameter_errors = definition.validate_parameters(action.parameters or {})
    reasons.extend(parameter_errors)

    agent = session.get(AgentRecord, action.target_agent_id)
    if agent is None:
        reasons.append("target agent does not exist")
    elif not agent.enabled:
        reasons.append("target agent is disabled")
    elif agent.host_id != action.target_host_id:
        reasons.append("target agent is not enrolled for target host")

    incident = session.get(IncidentRecord, action.incident_id)
    if incident is None:
        reasons.append("incident does not exist")
    elif action.target_host_id not in (incident.affected_hosts or []):
        reasons.append("target host is not affected by incident")

    host = session.get(HostRecord, action.target_host_id)
    if host is not None:
        os_name = (host.operating_system or "unknown").lower()
        if not any(value in os_name for value in definition.supported_os):
            reasons.append(f"action is not supported on target OS: {os_name}")

    if _utc(action.expires_at) <= _utc(now):
        reasons.append("action request has expired")

    if definition.approval_required:
        if not action.approval_id:
            reasons.append("approval is required")
        else:
            approval = session.get(ApprovalRecord, action.approval_id)
            if approval is None or approval.action_id != action.action_id:
                reasons.append("approval record is invalid")
            else:
                if approval.status != "approved":
                    reasons.append("approval is not approved")
                if _utc(approval.expires_at) <= _utc(now):
                    reasons.append("approval has expired")

    return not reasons, reasons
