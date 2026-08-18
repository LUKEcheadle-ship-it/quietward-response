from __future__ import annotations

from app.database.models import EventRecord


def timeline_for(events: list[EventRecord]) -> list[dict[str, object]]:
    return [
        {
            "event_id": event.event_id,
            "timestamp": event.occurred_at,
            "event_type": event.event_type,
            "summary": event.summary,
            "severity": event.severity,
            "evidence": event.payload.get("evidence") or {},
        }
        for event in sorted(events, key=lambda value: value.occurred_at)
    ]
