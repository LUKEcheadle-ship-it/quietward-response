from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.host import Host
from app.models.incident import Incident
from app.schemas.event import EventCreate
from app.services.audit_service import record_audit
from app.services.correlation import find_incident
from app.services.incident_service import refresh_incident


def ingest_event(db: Session, payload: EventCreate) -> dict:
    event_id = str(payload.event_id)
    if db.get(Event, event_id):
        record_audit(db, action="event.rejected", resource_type="event", resource_id=event_id, details={"reason": "duplicate event_id"})
        db.commit()
        raise HTTPException(status_code=409, detail="event_id has already been ingested")

    values = payload.model_dump(mode="python")
    values["event_id"] = event_id
    # Persist UTC as a naive value for consistent SQLite/PostgreSQL comparisons.
    values["timestamp"] = payload.timestamp.astimezone(timezone.utc).replace(tzinfo=None)
    values["event_metadata"] = values.pop("metadata")
    values["received_at"] = datetime.now(timezone.utc).replace(tzinfo=None)

    host = db.get(Host, payload.host_id)
    operating_system = str(payload.metadata.get("operating_system")) if payload.metadata.get("operating_system") else None
    if host is None:
        host = Host(host_id=payload.host_id, hostname=payload.host_name or payload.host_id, operating_system=operating_system,
                    agent=payload.source, agent_version=payload.source_version, first_seen=values["timestamp"],
                    last_seen=values["timestamp"], status="reporting")
        db.add(host)
    else:
        host.hostname = payload.host_name or host.hostname
        host.operating_system = operating_system or host.operating_system
        host.agent = payload.source
        host.agent_version = payload.source_version or host.agent_version
        host.first_seen = min(host.first_seen, values["timestamp"])
        host.last_seen = max(host.last_seen, values["timestamp"])
        host.status = "reporting"

    event = Event(**values)
    incident, reasons = find_incident(db, event)
    incident_created = incident is None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if incident is None:
        incident = Incident(title=f"Activity on {host.hostname}", status="new", severity=event.severity,
                            confidence=float(event.confidence), affected_hosts=[event.host_id], created_at=now,
                            updated_at=now, first_event_at=event.timestamp, last_event_at=event.timestamp,
                            event_count=0, probable_cause="Assessment pending", correlation_reasons=["initial event"],
                            recommended_actions=[])
        db.add(incident)
        db.flush()
        reasons = ["initial event opened incident"]
        record_audit(db, action="incident.created", resource_type="incident", resource_id=incident.incident_id, details={"trigger_event_id": event_id})
    else:
        incident.correlation_reasons = list(dict.fromkeys([*incident.correlation_reasons, *reasons]))

    event.incident_id = incident.incident_id
    db.add(event)
    db.flush()
    record_audit(db, action="event.received", resource_type="event", resource_id=event_id, details={"source": event.source, "host_id": event.host_id})
    record_audit(db, action="event.added_to_incident", resource_type="incident", resource_id=incident.incident_id,
                 details={"event_id": event_id, "reasons": reasons})
    refresh_incident(db, incident)
    db.commit()
    return {"event_id": event_id, "host_id": event.host_id, "incident_id": incident.incident_id,
            "incident_created": incident_created, "correlation_reasons": reasons}
