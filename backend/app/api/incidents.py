from __future__ import annotations

import base64
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select, func, or_, and_
from sqlalchemy.orm import Session

from app.database.models import IncidentRecord, EventRecord
from app.database.session import get_db
from app.schemas.incident import IncidentDetail, IncidentPatch, IncidentSummary
from app.services.incident_service import (
    incident_to_detail,
    incident_to_summary,
    update_incident,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _actor_id(value: str) -> str:
    resolved = value.strip() or "local-analyst"
    return resolved[:128]


@router.get("", response_model=list[IncidentSummary])
def list_incidents(
    incident_status: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    statement = select(IncidentRecord)
    if incident_status:
        statement = statement.where(IncidentRecord.status == incident_status)
    if severity:
        statement = statement.where(IncidentRecord.severity == severity.lower())
    incidents = list(
        db.scalars(statement.order_by(IncidentRecord.updated_at.desc()).limit(limit))
    )
    return [incident_to_summary(incident) for incident in incidents]


@router.get("/page")
def incident_page(
    status_filter: str | None = Query(default=None, alias="status", max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    host: str | None = Query(default=None, max_length=128),
    search: str | None = Query(default=None, max_length=120),
    cursor: str | None = Query(default=None, max_length=1024),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    filters = []
    if status_filter:
        filters.append(IncidentRecord.status == status_filter)
    if severity:
        filters.append(IncidentRecord.severity == severity.lower())
    if host:
        filters.append(IncidentRecord.incident_id.in_(select(EventRecord.incident_id).where(EventRecord.host_id == host)))
    if search:
        filters.append(or_(IncidentRecord.title.icontains(search, autoescape=True),
                           IncidentRecord.incident_id == search))
    total = db.scalar(select(func.count()).select_from(IncidentRecord).where(*filters)) or 0
    if cursor:
        try:
            value = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
            timestamp = datetime.fromisoformat(value["updated_at"])
            identity = value["id"]
            if not isinstance(identity, str) or len(identity) > 36:
                raise ValueError("invalid id")
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise HTTPException(status_code=422, detail="Invalid incident cursor") from exc
        filters.append(or_(IncidentRecord.updated_at < timestamp,
                           and_(IncidentRecord.updated_at == timestamp, IncidentRecord.incident_id < identity)))
    rows = list(db.scalars(select(IncidentRecord).where(*filters)
                          .order_by(IncidentRecord.updated_at.desc(), IncidentRecord.incident_id.desc()).limit(limit+1)))
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1]
        next_cursor = base64.urlsafe_b64encode(json.dumps({"updated_at": last.updated_at.isoformat(), "id": last.incident_id}).encode()).decode()
    return {"items": [incident_to_summary(row) for row in page], "total": total, "next_cursor": next_cursor}


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return incident_to_detail(db, incident)


@router.patch("/{incident_id}", response_model=IncidentDetail)
def patch_incident(
    incident_id: str,
    patch: IncidentPatch,
    db: Session = Depends(get_db),
    actor_id: str = Header(default="local-analyst", alias="X-Actor-ID"),
) -> dict[str, object]:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    updated = update_incident(db, incident, patch, actor_id=_actor_id(actor_id))
    return incident_to_detail(db, updated)
