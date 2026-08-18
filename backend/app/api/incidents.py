from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import IncidentRecord
from app.database.session import get_db
from app.schemas.incident import IncidentDetail, IncidentPatch, IncidentSummary
from app.services.incident_service import (
    incident_to_detail,
    incident_to_summary,
    update_incident,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


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
    updated = update_incident(db, incident, patch, actor_id=actor_id[:128])
    return incident_to_detail(db, updated)
