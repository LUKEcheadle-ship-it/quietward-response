from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.event import Event
from app.models.incident import Incident


def _value(event: Event, group: str, *keys: str):
    data = getattr(event, group) or {}
    for key in keys:
        if data.get(key) not in (None, ""):
            return str(data[key]).lower()
    return None


def correlation_reasons(incoming: Event, existing_events: list[Event]) -> list[str]:
    reasons = ["same host within 5-minute correlation window"]
    comparisons = [
        ("related process ID", "process", ("pid", "process_id")),
        ("related executable or file path", "file", ("path", "file_path")),
        ("related executable or file path", "process", ("executable", "path")),
        ("related destination address", "network", ("destination_address", "destination", "remote_address")),
        ("shared persistence mechanism", "persistence", ("mechanism", "type", "name")),
    ]
    if incoming.category and any(event.category == incoming.category for event in existing_events):
        reasons.append(f"related category: {incoming.category}")
    for label, group, keys in comparisons:
        incoming_value = _value(incoming, group, *keys)
        if incoming_value and any(_value(event, group, *keys) == incoming_value for event in existing_events):
            reasons.append(f"{label}: {incoming_value}")
    return list(dict.fromkeys(reasons))


def find_incident(db: Session, event: Event) -> tuple[Incident | None, list[str]]:
    cutoff = event.timestamp - timedelta(seconds=settings.correlation_window_seconds)
    candidates = list(db.scalars(select(Incident).join(Event).where(
        Event.host_id == event.host_id,
        Incident.status.notin_(["resolved", "dismissed"]),
        Incident.last_event_at >= cutoff,
        Incident.first_event_at <= event.timestamp + timedelta(seconds=settings.correlation_window_seconds),
    ).distinct().order_by(Incident.last_event_at.desc())).all())
    if not candidates:
        return None, []
    candidate = candidates[0]
    existing = list(db.scalars(select(Event).where(Event.incident_id == candidate.incident_id)).all())
    return candidate, correlation_reasons(event, existing)
