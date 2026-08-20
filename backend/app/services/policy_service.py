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


RECOMMENDATION_BINDING_REASON = "action is not an enabled recommendation for incident"
INCIDENT_STATUS_REASON = "incident status does not allow response actions"
_ACTIONABLE_INCIDENT_STATUSES = {"new", "investigating", "contained"}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _os_family(value: str | None) -> str:
    text = (value or "").strip().lower()
    if "windows" in text:
        return "windows"
    if "linux" in text:
        return "linux"
    if "darwin" in text or "macos" in text or "mac os" in text:
        return "darwin"
    return "unknown"


def incident_allows_response(incident: IncidentRecord) -> bool:
    return incident.status in _ACTIONABLE_INCIDENT_STATUSES


def incident_enables_action(incident: IncidentRecord, action_type: str) -> bool:
    """Return whether this open incident currently exposes the action."""
    if not incident_allows_response(incident):
        return False
    for recommendation in incident.recommended_actions or []:
        if not isinstance(recommendation, dict):
            continue
        if (
            recommendation.get("enabled") is True
            and recommendation.get("registry_action_type") == action_type
        ):
            return True
    return False


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
    else:
        if action.target_host_id not in (incident.affected_hosts or []):
            reasons.append("target host is not affected by incident")
        if not incident_allows_response(incident):
            reasons.append(INCIDENT_STATUS_REASON)
        elif not incident_enables_action(incident, action.action_type):
            reasons.append(RECOMMENDATION_BINDING_REASON)

    host = session.get(HostRecord, action.target_host_id)
    if host is not None:
        family = _os_family(host.operating_system)
        if family not in definition.supported_os:
            reasons.append(f"action is not supported on target OS family: {family}")

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
                # Bind the approval to the exact action/incident/request lifecycle,
                # not just to a status string. These fields are redundant by design
                # so policy can detect accidental/corrupt cross-linking before dispatch.
                if approval.incident_id != action.incident_id:
                    reasons.append("approval incident does not match action incident")
                if approval.requested_by != action.requested_by:
                    reasons.append("approval requester does not match action requester")
                if approval.status != "approved":
                    reasons.append("approval is not approved")
                else:
                    if not approval.approved_by or approval.approved_at is None:
                        reasons.append("approval decision metadata is incomplete")
                if _utc(approval.expires_at) <= _utc(now):
                    reasons.append("approval has expired")

    return not reasons, reasons
