from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import Audit
from app.models.event import Event
from app.models.incident import Incident
from app.services.audit_service import record_audit
from app.services.timeline import build_timeline

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _classify(events: list[Event]) -> str:
    words = " ".join(f"{event.event_type} {event.category or ''} {event.summary}" for event in events).lower()
    if any(word in words for word in ("persistence", "scheduled task", "autorun")):
        return "persistence"
    if any(word in words for word in ("listener", "wildcard bind", "exposed service")):
        return "listener"
    if any(word in words for word in ("disk", "service unavailable", "service failure")):
        return "disk"
    return "generic"


def recommendations_for(events: list[Event]) -> list[dict]:
    incident_type = _classify(events)
    diagnostics = {
        "persistence": ["Inspect executable metadata and signature", "Calculate and verify the executable hash", "Inspect the persistence entry", "Inspect the parent process", "Review related network connections"],
        "listener": ["Identify the owning process", "Inspect service configuration", "Determine the bind address and exposure", "Review recent configuration changes"],
        "disk": ["Identify the largest disk consumers", "Inspect recent storage growth", "Review relevant service and system logs", "Determine whether service health is affected"],
        "generic": ["Validate the source evidence", "Inspect related host activity", "Collect relevant process, file, and network context"],
    }[incident_type]
    remediation = {
        "persistence": ["Remove confirmed malicious persistence after approval"],
        "listener": ["Restrict confirmed unintended exposure after approval"],
        "disk": ["Reclaim capacity using an approved operational runbook"],
        "generic": ["Apply an approved corrective runbook after diagnosis"],
    }[incident_type]
    return ([{"type": "diagnostic", "title": item, "enabled": True} for item in diagnostics] +
            [{"type": "remediation", "title": item, "enabled": False, "note": "Phase 2 — not enabled"} for item in remediation])


def _assessment(events: list[Event]) -> tuple[str, str]:
    incident_type = _classify(events)
    if incident_type == "persistence":
        return "Potential persistence activity", "A new or unknown executable appears linked to a persistence mechanism and subsequent execution activity."
    if incident_type == "listener":
        return "Unexpected listening service", "A newly observed listener may expose an unexpected process or service on a broad bind address."
    if incident_type == "disk":
        return "Storage pressure affecting service health", "Rapid disk consumption appears temporally related to service degradation or unavailability."
    return f"Activity on {events[0].host_name or events[0].host_id}", "Related host activity occurred within the configured correlation window."


def refresh_incident(db: Session, incident: Incident) -> Incident:
    events = list(db.scalars(select(Event).where(Event.incident_id == incident.incident_id).order_by(Event.timestamp)).all())
    if not events:
        return incident
    title, cause = _assessment(events)
    recommendations = recommendations_for(events)
    incident.title = title
    incident.probable_cause = cause
    incident.severity = max((event.severity for event in events), key=lambda value: SEVERITY_RANK[value])
    incident.confidence = round(sum(event.confidence for event in events) / len(events), 1)
    incident.affected_hosts = sorted({event.host_id for event in events})
    incident.first_event_at = min(event.timestamp for event in events)
    incident.last_event_at = max(event.timestamp for event in events)
    incident.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    incident.event_count = len(events)
    if incident.recommended_actions != recommendations:
        incident.recommended_actions = recommendations
        record_audit(db, action="recommendation.generated", resource_type="incident", resource_id=incident.incident_id, details={"count": len(recommendations)})
    return incident


def serialize_event(event: Event) -> dict:
    return {
        "event_id": event.event_id, "schema_version": event.schema_version, "source": event.source,
        "source_version": event.source_version, "host_id": event.host_id, "host_name": event.host_name,
        "timestamp": event.timestamp, "event_type": event.event_type, "category": event.category,
        "severity": event.severity, "confidence": event.confidence, "summary": event.summary,
        "evidence": event.evidence, "process": event.process, "file": event.file,
        "network": event.network, "persistence": event.persistence, "metadata": event.event_metadata,
        "incident_id": event.incident_id, "received_at": event.received_at,
    }


def incident_detail(db: Session, incident: Incident) -> dict:
    events = list(db.scalars(select(Event).where(Event.incident_id == incident.incident_id).order_by(Event.timestamp)).all())
    audits = list(db.scalars(select(Audit).where(
        ((Audit.resource_type == "incident") & (Audit.resource_id == incident.incident_id)) |
        ((Audit.resource_type == "event") & (Audit.resource_id.in_([event.event_id for event in events])))
    ).order_by(Audit.timestamp)).all())
    return {
        "incident_id": incident.incident_id, "title": incident.title, "status": incident.status,
        "severity": incident.severity, "confidence": incident.confidence, "affected_hosts": incident.affected_hosts,
        "created_at": incident.created_at, "updated_at": incident.updated_at, "first_event_at": incident.first_event_at,
        "last_event_at": incident.last_event_at, "event_count": incident.event_count,
        "probable_cause": incident.probable_cause, "correlation_reasons": incident.correlation_reasons,
        "recommended_actions": incident.recommended_actions, "timeline": build_timeline(events),
        "events": [serialize_event(event) for event in events], "audit_trail": audits,
    }
