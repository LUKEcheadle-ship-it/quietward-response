from __future__ import annotations

from typing import Any

from app.database.models import EventRecord
from app.services.recommendation import (
    probable_cause_for,
    recommendations_for as base_recommendations_for,
)

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
    "known_bad_hash",
}
_HIGH_SEVERITIES = {"high", "critical"}


def _walk_markers(value: Any) -> set[str]:
    markers: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in {
                "suspicious_markers",
                "risk_markers",
                "security_markers",
            }:
                if isinstance(item, str):
                    candidates = [item]
                elif isinstance(item, (list, tuple, set)):
                    candidates = item
                else:
                    candidates = []
                markers.update(
                    str(candidate).strip().lower().replace("-", "_").replace(" ", "_")
                    for candidate in candidates
                    if str(candidate).strip()
                )
            elif normalized_key == "known_bad_hash" and item is True:
                markers.add("known_bad_hash")
            markers.update(_walk_markers(item))
    elif isinstance(value, list):
        for item in value:
            markers.update(_walk_markers(item))
    return markers


def _event_markers(event: EventRecord) -> set[str]:
    return _walk_markers(event.normalized or {}) | _walk_markers(event.payload or {})


def _process_termination_justified(events: list[EventRecord]) -> bool:
    for event in events:
        event_type = str(event.event_type or "").lower()
        severity = str(event.severity or "").lower()
        if event_type == "privilege_escalation" and severity in _HIGH_SEVERITIES:
            return True
        if (
            event_type == "process_start"
            and severity in _HIGH_SEVERITIES
            and _event_markers(event) & _HIGH_SIGNAL_MARKERS
        ):
            return True
    return False


def _file_quarantine_justified(events: list[EventRecord]) -> bool:
    for event in events:
        event_type = str(event.event_type or "").lower()
        severity = str(event.severity or "").lower()
        if event_type in {"malware_signature", "yara_match"}:
            return True
        if (
            event_type == "executable_created"
            and severity in _HIGH_SEVERITIES
        ):
            return True
        if (
            event_type in {"sensitive_file_change", "file_change"}
            and severity in _HIGH_SEVERITIES
            and "known_bad_hash" in _event_markers(event)
        ):
            return True
    return False


def recommendations_for(events: list[EventRecord]) -> list[dict[str, object]]:
    """Preserve broad investigation while requiring stronger evidence for mutation."""
    recommendations = list(base_recommendations_for(events))
    allow_process_termination = _process_termination_justified(events)
    allow_file_quarantine = _file_quarantine_justified(events)

    filtered: list[dict[str, object]] = []
    for recommendation in recommendations:
        action_type = recommendation.get("registry_action_type")
        if action_type == "terminate_process_by_handle" and not allow_process_termination:
            continue
        if action_type in {
            "quarantine_artifact_by_handle",
            "restore_quarantined_artifact_by_handle",
        } and not allow_file_quarantine:
            continue
        filtered.append(recommendation)
    return filtered


__all__ = ["probable_cause_for", "recommendations_for"]
