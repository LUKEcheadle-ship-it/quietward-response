from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.event import Event
from app.schemas.event import EventCreate, EventResponse, IngestionResult
from app.services.incident_service import serialize_event
from app.services.ingestion import ingest_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=IngestionResult, status_code=201)
def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> dict:
    return ingest_event(db, payload)


@router.get("", response_model=list[EventResponse])
def list_events(
    host: str | None = None,
    severity: str | None = None,
    event_type: str | None = Query(default=None, alias="event_type"),
    start: datetime | None = None,
    end: datetime | None = None,
    incident_id: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[dict]:
    query = select(Event)
    if host:
        query = query.where((Event.host_id == host) | (Event.host_name == host))
    if severity:
        query = query.where(Event.severity == severity)
    if event_type:
        query = query.where(Event.event_type == event_type)
    if start:
        query = query.where(Event.timestamp >= start)
    if end:
        query = query.where(Event.timestamp <= end)
    if incident_id:
        query = query.where(Event.incident_id == incident_id)
    events = db.scalars(query.order_by(Event.timestamp.desc()).limit(limit)).all()
    return [serialize_event(event) for event in events]
