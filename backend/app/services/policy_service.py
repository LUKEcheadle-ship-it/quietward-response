from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import (
    ActionRecord,
    AgentRecord,
    ApprovalRecord,
    EventRecord,
    HostRecord,
    IncidentRecord,
)
from app.services.action_registry import get_action_definition


RECOMMENDATION_BINDING_REASON = "action is not an enabled recommendation for incident"
INCIDENT_STATUS_REASON = "incident status does not allow response actions"
AGENT_CAPABILITY_MISSING_REASON = "target agent has not reported v1.2 capabilities"
AGENT_CAPABILITY_STALE_REASON = "target agent capability report is stale"
AGENT_CAPABILITY_DISABLED_REASON = "target agent has not enabled this action capability"
INTEGRITY_TRUST_REASON = "incident contains compromised evidence/sensor integrity; medium/high-impact mutation is blocked"
_ACTIONABLE_INCIDENT_STATUSES = {"new", "investigating", "contained"}
_LEGACY_CAPABILITY_EXEMPT_ACTIONS = {"restart_quietward_demo_service"}
_CAPABILITY_REPORT_MAX_AGE = timedelta(minutes=15)
_INTEGRITY_EVENT_TYPES = {
    "evidence_integrity_failure",
    "self_integrity_change",
    "sensor_integrity_failure",
    "agent_integrity_failure",
    "sensor_tamper",
    "agent_tamper",
    "audit_log_clear",
    "audit_log_cleared",
}


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


def incident_integrity_compromised(session: Session, incident_id: str) -> bool:
    """Detect explicit trust-failure evidence without depending on one sensor vendor.

    The check is intentionally conservative and bounded. A canonical integrity event,
    an integrity-category failure/tamper event, or an event name that explicitly
    states sensor/evidence/agent tamper is enough to freeze non-low-risk mutation.
    """
    rows = session.execute(
        select(EventRecord.event_type, EventRecord.category)
        .where(EventRecord.incident_id == incident_id)
        .order_by(EventRecord.occurred_at.desc())
        .limit(512)
    )
    for event_type, category in rows:
        event_text = str(event_type or "").strip().lower()
        category_text = str(category or "").strip().lower()
        if event_text in _INTEGRITY_EVENT_TYPES:
            return True
        if category_text == "integrity" and any(
            token in event_text for token in ("failure", "tamper", "self_integrity")
        ):
            return True
        if any(token in event_text for token in ("evidence_tamper", "sensor_tamper", "agent_tamper")):
            return True
    return False


def agent_capability_reason(
    agent: AgentRecord,
    action_type: str,
    *,
    now: datetime | None = None,
) -> str | None:
    """Return the fail-closed capability reason for one target agent/action."""
    if action_type in _LEGACY_CAPABILITY_EXEMPT_ACTIONS:
        return None
    if agent.capabilities_updated_at is None:
        return AGENT_CAPABILITY_MISSING_REASON
    resolved_now = _utc(now or datetime.now(timezone.utc))
    updated_at = _utc(agent.capabilities_updated_at)
    if updated_at > resolved_now + timedelta(seconds=30):
        return AGENT_CAPABILITY_STALE_REASON
    if updated_at < resolved_now - _CAPABILITY_REPORT_MAX_AGE:
        return AGENT_CAPABILITY_STALE_REASON
    if action_type not in set(agent.enabled_actions or []):
        return AGENT_CAPABILITY_DISABLED_REASON
    return None


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
    else:
        capability_reason = agent_capability_reason(
            agent,
            action.action_type,
            now=now,
        )
        if capability_reason:
            reasons.append(capability_reason)

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
        if (
            definition.risk_level in {"medium", "high", "critical"}
            and incident_integrity_compromised(session, incident.incident_id)
        ):
            reasons.append(INTEGRITY_TRUST_REASON)

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
                if approval.incident_id != action.incident_id:
                    reasons.append("approval incident does not match action incident")
                if approval.requested_by != action.requested_by:
                    reasons.append("approval requester does not match action requester")
                if approval.status != "approved":
                    reasons.append("approval is not approved")
                elif not approval.approved_by or approval.approved_at is None:
                    reasons.append("approval decision metadata is incomplete")
                if _utc(approval.expires_at) <= _utc(now):
                    reasons.append("approval has expired")

    return not reasons, reasons
