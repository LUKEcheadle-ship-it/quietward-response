from __future__ import annotations

from types import SimpleNamespace

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, IncidentRecord
from app.database.session import get_db
from app.schemas.incident import IncidentDetail, IncidentPatch, IncidentSummary
from app.schemas.response_plan import ResponsePlanRead
from app.services.incident_service import (
    incident_to_detail,
    incident_to_summary,
    update_incident,
)
from app.services.response_family import infer_response_family
from app.services.response_plan import build_response_plan

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


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    return incident_to_detail(db, incident)


@router.get("/{incident_id}/response-plan", response_model=ResponsePlanRead)
def get_response_plan(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    incident = db.get(IncidentRecord, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="incident not found")
    events = list(
        db.scalars(
            select(EventRecord)
            .where(EventRecord.incident_id == incident.incident_id)
            .order_by(EventRecord.occurred_at.asc(), EventRecord.event_id.asc())
        )
    )

    # Response plans are sensor-neutral. Normalize common external event vocabulary
    # into the canonical plan families without rewriting persisted evidence.
    normalized_events = []
    for event in events:
        family = infer_response_family(event.event_type, event.category)
        canonical_category = "file" if family == "file_integrity" else family
        normalized_events.append(
            SimpleNamespace(
                event_type=event.event_type,
                category=canonical_category,
            )
        )
    return build_response_plan(incident, normalized_events)


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
