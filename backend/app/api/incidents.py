from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.event import Event
from app.models.host import Host
from app.models.incident import Incident
from app.schemas.incident import IncidentDetail, IncidentResponse, IncidentUpdate
from app.services.audit_service import record_audit
from app.services.incident_service import incident_detail

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)) -> dict:
    active = db.scalar(select(func.count()).select_from(Incident).where(Incident.status.notin_(["resolved", "dismissed"]))) or 0
    critical = db.scalar(select(func.count()).select_from(Incident).where(Incident.severity == "critical", Incident.status.notin_(["resolved", "dismissed"]))) or 0
    high = db.scalar(select(func.count()).select_from(Incident).where(Incident.severity == "high", Incident.status.notin_(["resolved", "dismissed"]))) or 0
    hosts = db.scalar(select(func.count()).select_from(Host)) or 0
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    recent_events = db.scalar(select(func.count()).select_from(Event).where(Event.timestamp >= cutoff)) or 0
    recent = db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(6)).all()
    return {"active_incidents": active, "critical_incidents": critical, "high_incidents": high,
            "hosts_reporting": hosts, "events_last_24h": recent_events,
            "recent_incidents": [{"incident_id": item.incident_id, "title": item.title, "severity": item.severity,
                                  "status": item.status, "created_at": item.created_at} for item in recent]}


@router.get("", response_model=list[IncidentResponse])
def list_incidents(status: str | None = None, severity: str | None = None,
                   limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    return db.scalars(query.order_by(Incident.updated_at.desc()).limit(limit)).all()


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident_detail(db, incident)


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: str, payload: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    changes = payload.model_dump(exclude_none=True)
    for field, value in changes.items():
        old = getattr(incident, field)
        if old != value:
            setattr(incident, field, value)
            action = "incident.status_changed" if field == "status" else "incident.severity_changed"
            record_audit(db, action=action, resource_type="incident", resource_id=incident_id,
                         actor_type="analyst", actor_id="local-user", details={"from": old, "to": value})
    incident.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    return incident
