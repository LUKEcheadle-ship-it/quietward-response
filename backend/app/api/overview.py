from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, HostRecord, IncidentRecord
from app.database.session import get_db
from app.services.incident_service import incident_to_summary

router = APIRouter(prefix="/api/v1/overview", tags=["overview"])


@router.get("")
def overview(db: Session = Depends(get_db)) -> dict[str, object]:
    active = db.scalar(
        select(func.count(IncidentRecord.incident_id)).where(
            IncidentRecord.status.in_(("new", "investigating", "contained"))
        )
    ) or 0
    critical = db.scalar(
        select(func.count(IncidentRecord.incident_id)).where(
            IncidentRecord.severity == "critical"
        )
    ) or 0
    high = db.scalar(
        select(func.count(IncidentRecord.incident_id)).where(
            IncidentRecord.severity == "high"
        )
    ) or 0
    hosts = db.scalar(select(func.count(HostRecord.host_id))) or 0
    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    events = db.scalar(
        select(func.count(EventRecord.event_id)).where(EventRecord.occurred_at >= day_ago)
    ) or 0
    recent = list(
        db.scalars(select(IncidentRecord).order_by(IncidentRecord.created_at.desc()).limit(6))
    )
    return {
        "active_incidents": active,
        "critical_incidents": critical,
        "high_incidents": high,
        "hosts_reporting": hosts,
        "events_last_24h": events,
        "recent_incidents": [incident_to_summary(incident) for incident in recent],
        "remediation_enabled": False,
    }
