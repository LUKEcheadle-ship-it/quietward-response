from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, HostRecord, IncidentRecord
from app.database.session import get_db
from app.services.incident_service import incident_to_summary

router = APIRouter(prefix="/api/v1/overview", tags=["overview"])


@router.get("/bridge")
def bridge_status(db: Session = Depends(get_db)) -> dict[str, object]:
    # Receipt time describes transport freshness; original observation time can
    # legitimately be old after an offline queue is delivered.
    latest = db.scalar(select(EventRecord).where(EventRecord.source == "quietward")
                       .order_by(EventRecord.received_at.desc()).limit(1))
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    count = db.scalar(select(func.count()).select_from(EventRecord).where(
        EventRecord.source == "quietward", EventRecord.received_at >= day_ago)) or 0
    received = latest.received_at if latest is not None else None
    if received is not None and received.tzinfo is None:
        received = received.replace(tzinfo=timezone.utc)
    age = max(0, (now-received).total_seconds()) if received else None
    return {"state": "no_data" if age is None else "recent" if age <= 3600 else "idle",
            "last_received_at": received.isoformat() if received else None,
            "received_last_24h": count, "source_version": latest.source_version if latest else None,
            "pending_handoffs": None,
            "note": "Receipt activity only. Idle may mean no new findings; endpoint queue depth is not available here."}


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
