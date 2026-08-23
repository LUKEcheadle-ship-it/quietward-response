from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord
from app.database.session import get_db
from app.schemas.event import EventCreate, EventRead, IngestionResult
from app.services.agent_auth import verify_agent_event_request
from app.services.audit_service import record_audit
from app.services.incident_service import event_to_dict
from app.services.ingestion import (
    DuplicateEventError,
    EventIdConflictError,
    ingest_event,
)

router = APIRouter(prefix="/api/v1/events", tags=["events"])


def _audit_rejection(
    db: Session,
    *,
    actor_type: str,
    actor_id: str,
    payload: EventCreate,
    reason: str,
    details: dict[str, object] | None = None,
) -> None:
    record_audit(
        db,
        actor_type=actor_type,
        actor_id=actor_id[:128],
        action="event_rejected",
        resource_type="event",
        resource_id=str(payload.event_id),
        details={"reason": reason, **(details or {})},
    )
    db.commit()


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
        # QuietWard ingestion uses a derived event-only HMAC subkey. That subkey is
        # deliberately not accepted by capability/polling/rotation/action-result
        # routes, so compromise of the read-only adapter does not grant response
        # execution authority.
        agent = verify_agent_event_request(
            db,
            request,
            raw,
            replay_window_seconds=settings.agent_replay_window_seconds,
        )
        if agent.host_id != payload.host_id:
            _audit_rejection(
                db,
                actor_type="sensor_adapter",
                actor_id=agent.agent_id,
                payload=payload,
                reason="agent_host_mismatch",
                details={
                    "enrolled_host_id": agent.host_id,
                    "claimed_host_id": payload.host_id,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"code": "agent_host_mismatch"},
            )

        maximum_event_time = datetime.now(timezone.utc) + timedelta(
            seconds=settings.agent_replay_window_seconds
        )
        event_time = payload.timestamp.astimezone(timezone.utc)
        if event_time > maximum_event_time:
            _audit_rejection(
                db,
                actor_type="sensor_adapter",
                actor_id=agent.agent_id,
                payload=payload,
                reason="event_timestamp_too_far_in_future",
                details={
                    "event_timestamp": event_time.isoformat(),
                    "maximum_event_timestamp": maximum_event_time.isoformat(),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "event_timestamp_too_far_in_future"},
            )
    elif source != "quietward" and settings.environment.strip().lower() != "development":
        _audit_rejection(
            db,
            actor_type="unauthenticated_sensor",
            actor_id=source or "unknown",
            payload=payload,
            reason="unauthenticated_sensor_source",
        )
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
    except EventIdConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "event_id_conflict", "event_id": str(exc)},
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
