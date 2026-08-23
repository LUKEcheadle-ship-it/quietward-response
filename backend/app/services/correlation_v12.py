from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, IncidentRecord, utcnow
from app.models.event import highest_severity
from app.models.incident import incident_title
from app.services.audit_service import record_audit
from app.services.recommendation_v12 import probable_cause_for, recommendations_for
from app.services.response_family import infer_response_family

_ACTIONABLE_INCIDENT_STATUSES = ("new", "investigating", "contained")
_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_HIGH_SIGNAL_MARKERS = {
    "reverse_shell",
    "web_shell",
    "credential_dumping",
    "credential_theft",
    "process_injection",
    "document_spawned_interpreter",
    "server_spawned_suspicious_shell",
    "web_server_spawned_suspicious_shell",
    "ransomware_recovery_inhibition",
    "event_log_clearing",
    "credential_spray",
    "known_bad_hash",
    "docker_socket_mount",
    "host_root_mount",
}
_HIGH_SIGNAL_TYPES = {
    "malware_signature",
    "yara_match",
    "privilege_escalation",
    "container_escape_indicator",
    "evidence_integrity_failure",
    "self_integrity_change",
}
_STAGE_TRANSITIONS = {
    frozenset(("identity", "privilege")),
    frozenset(("execution", "privilege")),
    frozenset(("execution", "persistence")),
    frozenset(("execution", "network")),
    frozenset(("malware", "execution")),
    frozenset(("malware", "file_integrity")),
    frozenset(("malware", "network")),
    frozenset(("privilege", "persistence")),
    frozenset(("privilege", "network")),
    frozenset(("persistence", "network")),
    frozenset(("container", "execution")),
    frozenset(("container", "network")),
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _values(value: dict[str, Any], *keys: str) -> set[str]:
    result: set[str] = set()
    for key in keys:
        raw = value.get(key)
        if raw not in (None, ""):
            result.add(str(raw).strip().lower())
    return result


def _markers(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).strip().lower()
            if normalized in {"suspicious_markers", "risk_markers", "security_markers"}:
                if isinstance(item, str):
                    candidates = [item]
                elif isinstance(item, (list, tuple, set)):
                    candidates = item
                else:
                    candidates = []
                result.update(
                    str(candidate).strip().lower().replace("-", "_").replace(" ", "_")
                    for candidate in candidates
                    if str(candidate).strip()
                )
            elif normalized == "known_bad_hash" and item is True:
                result.add("known_bad_hash")
            result.update(_markers(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_markers(item))
    return result


def _indicator_sets(event: EventRecord) -> dict[str, set[str]]:
    normalized = _mapping(event.normalized)
    process = _mapping(normalized.get("process"))
    file_value = _mapping(normalized.get("file"))
    network = _mapping(normalized.get("network"))
    persistence = _mapping(normalized.get("persistence"))

    process_names = _values(process, "command_name", "path", "executable", "image")
    process_names |= _values(network, "process_name")
    return {
        "process identifier": _values(process, "pid", "process_id"),
        "process image/name": process_names,
        "file identity": _values(file_value, "path", "sha256", "hash", "subject"),
        "network destination": _values(
            network,
            "destination_address",
            "remote_address",
            "destination",
            "destination_hash",
            "remote_address_hash",
        ),
        "persistence identity": _values(
            persistence,
            "mechanism",
            "name",
            "path",
            "subject",
            "current_fingerprint",
        ),
    }


def _shared_indicator_reasons(current: EventRecord, previous: EventRecord) -> list[str]:
    left = _indicator_sets(current)
    right = _indicator_sets(previous)
    return [
        f"shared {label}"
        for label in left
        if left[label] and left[label] & right[label]
    ]


def _family(event: EventRecord) -> str:
    return infer_response_family(str(event.event_type or ""), str(event.category or ""))


def _explicit_high_signal(event: EventRecord) -> bool:
    event_type = str(event.event_type or "").strip().lower()
    if event_type in _HIGH_SIGNAL_TYPES:
        return True
    return bool(
        _markers(event.normalized or {}) & _HIGH_SIGNAL_MARKERS
        or _markers(event.payload or {}) & _HIGH_SIGNAL_MARKERS
    )


def _stage_reason(current: EventRecord, previous: EventRecord) -> str | None:
    current_family = _family(current)
    previous_family = _family(previous)
    if current_family == previous_family:
        return None
    if frozenset((current_family, previous_family)) not in _STAGE_TRANSITIONS:
        return None
    if not (_explicit_high_signal(current) or _explicit_high_signal(previous)):
        return None
    highest = max(
        _SEVERITY_RANK.get(str(current.severity or "").lower(), -1),
        _SEVERITY_RANK.get(str(previous.severity or "").lower(), -1),
    )
    if highest < _SEVERITY_RANK["high"]:
        return None
    return f"compatible high-signal attack stages: {previous_family} -> {current_family}"


def correlation_reasons(current: EventRecord, previous: EventRecord) -> list[str]:
    reasons = ["same host within the configured correlation window"]
    reasons.extend(_shared_indicator_reasons(current, previous))
    stage = _stage_reason(current, previous)
    if stage:
        reasons.append(stage)
    return reasons


def _qualifies(reasons: list[str]) -> bool:
    return any(
        reason.startswith("shared ")
        or reason.startswith("compatible high-signal attack stages:")
        for reason in reasons
    )


def _refresh_incident(session: Session, incident: IncidentRecord) -> None:
    events = list(
        session.scalars(
            select(EventRecord)
            .where(EventRecord.incident_id == incident.incident_id)
            .order_by(EventRecord.occurred_at.asc())
        )
    )
    incident.event_count = len(events)
    incident.first_event_at = events[0].occurred_at
    incident.last_event_at = events[-1].occurred_at
    incident.updated_at = utcnow()
    incident.affected_hosts = sorted({event.host_id for event in events})
    incident.severity = highest_severity(*(event.severity for event in events))
    incident.confidence = round(max(event.confidence for event in events), 3)
    incident.probable_cause = probable_cause_for(events)
    new_actions = recommendations_for(events)
    if incident.recommended_actions != new_actions:
        incident.recommended_actions = new_actions
        record_audit(
            session,
            actor_type="system",
            actor_id="rule-engine-v12",
            action="recommendation_generated",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"recommendation_count": len(new_actions), "mode": "rule_based_v12"},
            incident_id=incident.incident_id,
        )


def correlate_event(
    session: Session,
    event: EventRecord,
    *,
    correlation_window_seconds: int,
) -> tuple[IncidentRecord, list[str]]:
    window = timedelta(seconds=correlation_window_seconds)
    earliest = event.occurred_at - window
    latest = event.occurred_at + window
    recent = list(
        session.scalars(
            select(EventRecord)
            .join(IncidentRecord, EventRecord.incident_id == IncidentRecord.incident_id)
            .where(
                EventRecord.host_id == event.host_id,
                EventRecord.event_id != event.event_id,
                EventRecord.occurred_at >= earliest,
                EventRecord.occurred_at <= latest,
                EventRecord.incident_id.is_not(None),
                IncidentRecord.status.in_(_ACTIONABLE_INCIDENT_STATUSES),
            )
            .order_by(EventRecord.occurred_at.desc())
            .limit(100)
        )
    )

    candidates: dict[str, list[str]] = defaultdict(list)
    for previous in recent:
        reasons = correlation_reasons(event, previous)
        if _qualifies(reasons) and previous.incident_id:
            candidates[previous.incident_id].extend(reasons)

    selected_id = None
    selected_reasons: list[str] = []
    if candidates:
        selected_id, raw_reasons = max(
            candidates.items(), key=lambda item: (len(set(item[1])), item[0])
        )
        selected_reasons = sorted(set(raw_reasons))

    if selected_id:
        incident = session.get(IncidentRecord, selected_id)
        assert incident is not None
        event.incident_id = incident.incident_id
        incident.correlation_reasons = sorted(
            set(incident.correlation_reasons) | set(selected_reasons)
        )
        record_audit(
            session,
            actor_type="system",
            actor_id="correlation-engine-v12",
            action="event_added_to_incident",
            resource_type="event",
            resource_id=event.event_id,
            details={"correlation_reasons": selected_reasons},
            incident_id=incident.incident_id,
        )
    else:
        selected_reasons = ["incident opened from the first independently reportable event on this host"]
        incident = IncidentRecord(
            title=incident_title(event.category, event.host_name, event.summary),
            status="new",
            severity=event.severity,
            confidence=event.confidence,
            affected_hosts=[event.host_id],
            first_event_at=event.occurred_at,
            last_event_at=event.occurred_at,
            event_count=1,
            probable_cause="Assessment pending",
            correlation_reasons=selected_reasons,
            recommended_actions=[],
        )
        session.add(incident)
        session.flush()
        event.incident_id = incident.incident_id
        record_audit(
            session,
            actor_type="system",
            actor_id="correlation-engine-v12",
            action="incident_created",
            resource_type="incident",
            resource_id=incident.incident_id,
            details={"trigger_event_id": event.event_id},
            incident_id=incident.incident_id,
        )

    session.flush()
    _refresh_incident(session, incident)
    session.flush()
    return incident, selected_reasons
