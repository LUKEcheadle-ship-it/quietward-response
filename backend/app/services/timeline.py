from app.models.event import Event


def build_timeline(events: list[Event]) -> list[dict]:
    return [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "summary": event.summary,
            "severity": event.severity,
            "evidence": event.evidence,
        }
        for event in sorted(events, key=lambda item: item.timestamp)
    ]
