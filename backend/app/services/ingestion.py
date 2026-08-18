from __future__ import annotations

from datetime import timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database.models import EventRecord, HostRecord
from app.schemas.event import EventCreate
from app.services.audit_service import record_audit
from app.services.correlation import correlate_event


class DuplicateEventError(ValueError):
    """The same event ID and accepted payload were already persisted."""


class EventIdConflictError(ValueError):
    """An existing event ID was reused with different event content."""


def _record_event_rejection(
    session: Session,
    *,
    event_id: str,
    source: str,
    reason: str,
) -> None:
    record_audit(
        session,
        actor_type="sensor",
        actor_id=source,
        action="event_rejected",
        resource_type="event",
        resource_id=event_id,
        details={"reason": reason},
    )
    session.commit()


def _incoming_payload(event: EventCreate) -> dict[str, Any]:
    # Pydantic has already normalized compatibility aliases (for example QuietWard
    # `info` -> canonical `informational`), so this representation is stable across
    # wire-compatible retries.
    return event.model_dump(mode="json")


def _raise_duplicate_or_conflict(
    session: Session,
    *,
    existing: EventRecord,
    event: EventCreate,
) -> None:
    incoming = _incoming_payload(event)
    if (existing.payload or {}) == incoming:
        reason = "duplicate_event_id"
        _record_event_rejection(
            session,
            event_id=existing.event_id,
            source=event.source,
            reason=reason,
        )
        raise DuplicateEventError(existing.event_id)

    reason = "event_id_conflict"
    _record_event_rejection(
        session,
        event_id=existing.event_id,
        source=event.source,
        reason=reason,
    )
    raise EventIdConflictError(existing.event_id)


def normalize_event(event: EventCreate) -> dict[str, Any]:
    payload = _incoming_payload(event)
    payload["event_type"] = event.event_type.strip().lower().replace(" ", "_")
    payload["category"] = (
        event.category.strip().lower().replace(" ", "_") if event.category else None
    )
    payload["summary"] = " ".join(event.summary.split())
    payload["timestamp"] = event.timestamp.astimezone(timezone.utc).isoformat()
    return payload


def ingest_event(
    session: Session,
    event: EventCreate,
    *,
    correlation_window_seconds: int,
) -> tuple[EventRecord, str, list[str]]:
    event_id = str(event.event_id)
    existing = session.get(EventRecord, event_id)
    if existing is not None:
        _raise_duplicate_or_conflict(session, existing=existing, event=event)

    normalized = normalize_event(event)
    host = session.get(HostRecord, event.host_id)
    hostname = event.host_name or event.host_id
    operating_system = str(event.metadata.get("operating_system") or "") or None
    if host is None:
        host = HostRecord(
            host_id=event.host_id,
            hostname=hostname,
            operating_system=operating_system,
            agent=event.source,
            agent_version=event.source_version,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            status="reporting",
        )
        session.add(host)
    else:
        existing_first_seen = host.first_seen
        if existing_first_seen.tzinfo is None:
            existing_first_seen = existing_first_seen.replace(tzinfo=timezone.utc)
        host.hostname = hostname
        host.operating_system = operating_system or host.operating_system
        host.agent = event.source
        host.agent_version = event.source_version or host.agent_version
        existing_last_seen = host.last_seen
        if existing_last_seen.tzinfo is None:
            existing_last_seen = existing_last_seen.replace(tzinfo=timezone.utc)
        host.first_seen = min(existing_first_seen, event.timestamp)
        host.last_seen = max(existing_last_seen, event.timestamp)
        host.status = "reporting"

    record = EventRecord(
        event_id=event_id,
        schema_version=event.schema_version,
        source=event.source,
        source_version=event.source_version,
        host_id=event.host_id,
        host_name=hostname,
        occurred_at=event.timestamp,
        event_type=str(normalized["event_type"]),
        category=normalized["category"],
        severity=event.severity.value,
        confidence=event.confidence,
        summary=str(normalized["summary"]),
        payload=_incoming_payload(event),
        normalized=normalized,
    )
    session.add(record)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        existing = session.get(EventRecord, event_id)
        if existing is not None:
            _raise_duplicate_or_conflict(session, existing=existing, event=event)
        raise
    record_audit(
        session,
        actor_type="sensor",
        actor_id=event.source,
        action="event_received",
        resource_type="event",
        resource_id=event_id,
        details={"schema_version": event.schema_version, "host_id": event.host_id},
    )
    incident, reasons = correlate_event(
        session,
        record,
        correlation_window_seconds=correlation_window_seconds,
    )
    session.commit()
    session.refresh(record)
    return record, incident.incident_id, reasons
