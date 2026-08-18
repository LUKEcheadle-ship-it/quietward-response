from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord
from app.database.session import get_db
from app.schemas.event import EventCreate, EventRead, IngestionResult
from app.services.agent_auth import verify_agent_request
from app.services.incident_service import event_to_dict
from app.services.ingestion import DuplicateEventError, ingest_event

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def receive_event(
    payload: EventCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> IngestionResult:
    settings = request.app.state.settings
    source = payload.source.strip().lower()

    if settings.require_agent_auth_for_quietward_events and source == "quietward":
        raw = await request.body()
        agent = verify_agent_request(
            db,
            request,
            raw,
            replay_window_seconds=settings.agent_replay_window_seconds,
        )
        if agent.host_id != payload.host_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "agent_host_mismatch"},
            )
    elif source != "quietward" and settings.environment.strip().lower() != "development":
        # Sensor-neutral synthetic adapters are convenient for local demos, but they
        # are not authenticated identities. Fail closed outside development until a
        # source has its own authenticated adapter/trust contract.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "unauthenticated_sensor_source"},
        )

    try:
        event, incident_id, reasons = ingest_event(
            db,
            payload,
            correlation_window_seconds=settings.correlation_window_seconds,
        )
    except DuplicateEventError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "duplicate_event_id", "event_id": str(exc)},
        ) from exc
    return IngestionResult(
        accepted=True,
        event_id=event.event_id,
        host_id=event.host_id,
        incident_id=incident_id,
        correlation_reasons=reasons,
    )


@router.get("", response_model=list[EventRead])
def list_events(
    host: str | None = None,
    severity: str | None = None,
    event_type: str | None = Query(default=None, alias="event_type"),
    start: datetime | None = None,
    end: datetime | None = None,
    incident_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    statement = select(EventRecord)
    if host:
        statement = statement.where(EventRecord.host_id == host)
    if severity:
        statement = statement.where(EventRecord.severity == severity.lower())
    if event_type:
        statement = statement.where(EventRecord.event_type == event_type.lower())
    if start:
        statement = statement.where(EventRecord.occurred_at >= start)
    if end:
        statement = statement.where(EventRecord.occurred_at <= end)
    if incident_id:
        statement = statement.where(EventRecord.incident_id == incident_id)
    events = list(db.scalars(statement.order_by(EventRecord.occurred_at.desc()).limit(limit)))
    return [event_to_dict(event) for event in events]
