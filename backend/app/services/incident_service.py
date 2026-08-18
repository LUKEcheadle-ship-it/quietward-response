from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AuditRecord, EventRecord, IncidentRecord
from app.schemas.incident import IncidentPatch
from app.services.action_service import cancel_undispatched_actions_for_incident
from app.services.audit_service import record_audit
from app.services.timeline import timeline_for


def event_to_dict(event: EventRecord) -> dict[str, Any]:
    payload = event.payload
    return {
        "event_id": event.event_id,
        "schema_version": event.schema_version,
        "source": event.source,
        "source_version": event.source_version,
        "host_id": event.host_id,
        "host_name": event.host_name,
        "timestamp": event.occurred_at,
        "event_type": event.event_type,
        "category": event.category,
        "severity": event.severity,
        "confidence": event.confidence,
        "summary": event.summary,
        "incident_id": event.incident_id,
        "received_at": event.received_at,
        "evidence": payload.get("evidence") or {},
        "process": payload.get("process"),
        "file": payload.get("file"),
        "network": payload.get("network"),
        "persistence": payload.get("persistence"),
        "metadata": payload.get("metadata") or {},
    }


def incident_to_summary(incident: IncidentRecord) -> dict[str, Any]:
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "affected_hosts": incident.affected_hosts,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "first_event_at": incident.first_event_at,
        "last_event_at": incident.last_event_at,
        "event_count": incident.event_count,
        "probable_cause": incident.probable_cause,
        "correlation_reasons": incident.correlation_reasons,
        "recommended_actions": incident.recommended_actions,
    }


def incident_to_detail(session: Session, incident: IncidentRecord) -> dict[str, Any]:
    events = list(
        session.scalars(
            select(EventRecord)
            .where(EventRecord.incident_id == incident.incident_id)
            .order_by(EventRecord.occurred_at.asc())
        )
    )
    audits = list(
        session.scalars(
            select(AuditRecord)
            .where(AuditRecord.incident_id == incident.incident_id)
            .order_by(AuditRecord.timestamp.asc())
        )
    )
    return {
        **incident_to_summary(incident),
        "timeline": timeline_for(events),
        "events": [event_to_dict(event) for event in events],
        "audit_trail": [
            {
                "audit_id": audit.audit_id,
                "timestamp": audit.timestamp,
                "actor_type": audit.actor_type,
                "actor_id": audit.actor_id,
                "action": audit.action,
                "resource_type": audit.resource_type,
                "resource_id": audit.resource_id,
                "details": audit.details,
            }
            for audit in audits
        ],
    }


def update_incident(
    session: Session,
    incident: IncidentRecord,
    patch: IncidentPatch,
    *,
    actor_id: str,
) -> IncidentRecord:
    if patch.status is not None and patch.status != incident.status:
        previous = incident.status
        incident.status = patch.status
        record_audit(
            session,
            actor_type="analyst",
            actor_id=actor_id,
            action="incident_status_changed",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"previous": previous, "current": incident.status},
            incident_id=incident.incident_id,
        )
        if incident.status in {"resolved", "dismissed"}:
            cancel_undispatched_actions_for_incident(
                session,
                incident.incident_id,
                reason=f"incident moved to {incident.status}",
            )
    if patch.severity is not None and patch.severity.value != incident.severity:
        previous = incident.severity
        incident.severity = patch.severity.value
        record_audit(
            session,
            actor_type="analyst",
            actor_id=actor_id,
            action="severity_changed",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"previous": previous, "current": incident.severity},
            incident_id=incident.incident_id,
        )
    session.commit()
    session.refresh(incident)
    return incident
