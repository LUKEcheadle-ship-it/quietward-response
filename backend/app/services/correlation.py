from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, IncidentRecord, utcnow
from app.models.event import highest_severity
from app.models.incident import incident_title
from app.services.audit_service import record_audit
from app.services.recommendation import probable_cause_for, recommendations_for

_ACTIONABLE_INCIDENT_STATUSES = ("new", "investigating", "contained")


def _values(payload: dict[str, Any], section: str, keys: tuple[str, ...]) -> set[str]:
    value = payload.get(section) or {}
    if not isinstance(value, dict):
        return set()
    return {str(value[key]).lower() for key in keys if value.get(key) not in (None, "")}


def correlation_reasons(current: EventRecord, previous: EventRecord) -> list[str]:
    reasons = ["same host within the configured correlation window"]
    if current.category and current.category == previous.category:
        reasons.append(f"shared category: {current.category}")

    pairs = (
        ("process", ("pid", "process_id"), "related process identifier"),
        ("process", ("path", "executable", "image"), "related executable path"),
        ("file", ("path", "sha256", "hash"), "related file path or hash"),
        ("network", ("destination_address", "remote_address", "destination"), "related network destination"),
        ("persistence", ("mechanism", "name", "path"), "shared persistence mechanism"),
    )
    for section, keys, label in pairs:
        if _values(current.normalized, section, keys) & _values(previous.normalized, section, keys):
            reasons.append(label)
    return reasons


def _refresh_incident(session: Session, incident: IncidentRecord) -> None:
    events = list(
        session.scalars(
            select(EventRecord)
            .where(EventRecord.incident_id == incident.incident_id)
            .order_by(EventRecord.occurred_at.asc())
        )
    )
    incident.event_count = len(events)
    incident.first_event_at = events[0].occurred_at
    incident.last_event_at = events[-1].occurred_at
    incident.updated_at = utcnow()
    incident.affected_hosts = sorted({event.host_id for event in events})
    incident.severity = highest_severity(*(event.severity for event in events))
    incident.confidence = round(max(event.confidence for event in events), 3)
    incident.probable_cause = probable_cause_for(events)
    new_actions = recommendations_for(events)
    if incident.recommended_actions != new_actions:
        incident.recommended_actions = new_actions
        record_audit(
            session,
            actor_type="system",
            actor_id="rule-engine-v1",
            action="recommendation_generated",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"recommendation_count": len(new_actions), "mode": "rule_based"},
            incident_id=incident.incident_id,
        )


def correlate_event(
    session: Session,
    event: EventRecord,
    *,
    correlation_window_seconds: int,
) -> tuple[IncidentRecord, list[str]]:
    window = timedelta(seconds=correlation_window_seconds)
    earliest = event.occurred_at - window
    latest = event.occurred_at + window
    recent = list(
        session.scalars(
            select(EventRecord)
            .join(IncidentRecord, EventRecord.incident_id == IncidentRecord.incident_id)
            .where(
                EventRecord.host_id == event.host_id,
                EventRecord.event_id != event.event_id,
                EventRecord.occurred_at >= earliest,
                EventRecord.occurred_at <= latest,
                EventRecord.incident_id.is_not(None),
                IncidentRecord.status.in_(_ACTIONABLE_INCIDENT_STATUSES),
            )
            .order_by(EventRecord.occurred_at.desc())
            .limit(100)
        )
    )

    candidates: dict[str, list[str]] = defaultdict(list)
    for previous in recent:
        reasons = correlation_reasons(event, previous)
        if len(reasons) >= 2 and previous.incident_id:
            candidates[previous.incident_id].extend(reasons)

    selected_id = None
    selected_reasons: list[str] = []
    if candidates:
        selected_id, raw_reasons = max(
            candidates.items(), key=lambda item: (len(set(item[1])), item[0])
        )
        selected_reasons = sorted(set(raw_reasons))

    if selected_id:
        incident = session.get(IncidentRecord, selected_id)
        assert incident is not None
        event.incident_id = incident.incident_id
        incident.correlation_reasons = sorted(
            set(incident.correlation_reasons) | set(selected_reasons)
        )
        record_audit(
            session,
            actor_type="system",
            actor_id="correlation-engine-v1",
            action="event_added_to_incident",
            resource_type="event",
            resource_id=event.event_id,
            details={"correlation_reasons": selected_reasons},
            incident_id=incident.incident_id,
        )
    else:
        selected_reasons = ["incident opened from the first reportable event on this host"]
        incident = IncidentRecord(
            title=incident_title(event.category, event.host_name, event.summary),
            status="new",
            severity=event.severity,
            confidence=event.confidence,
            affected_hosts=[event.host_id],
            first_event_at=event.occurred_at,
            last_event_at=event.occurred_at,
            event_count=1,
            probable_cause="Assessment pending",
            correlation_reasons=selected_reasons,
            recommended_actions=[],
        )
        session.add(incident)
        session.flush()
        event.incident_id = incident.incident_id
        record_audit(
            session,
            actor_type="system",
            actor_id="correlation-engine-v1",
            action="incident_created",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"trigger_event_id": event.event_id},
            incident_id=incident.incident_id,
        )

    session.flush()
    _refresh_incident(session, incident)
    session.flush()
    return incident, selected_reasons
