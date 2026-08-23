from __future__ import annotations

from typing import Any

from app.database.models import EventRecord
from app.services.recommendation import (
    probable_cause_for,
    recommendations_for as base_recommendations_for,
)
from app.services.response_family import infer_response_family

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


def _controlled_diagnostic(action_type: str, title: str, description: str) -> dict[str, object]:
    return {
        "action_type": "diagnostic",
        "title": title,
        "description": description,
        "enabled": True,
        "phase": "v1.2 — approval required",
        "registry_action_type": action_type,
        "requires_approval": True,
    }


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


def _families(events: list[EventRecord]) -> set[str]:
    return {
        infer_response_family(str(event.event_type or ""), str(event.category or ""))
        for event in events
    }


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
        if event_type == "executable_created" and severity in _HIGH_SEVERITIES:
            return True
        if (
            event_type in {"sensitive_file_change", "file_change"}
            and severity in _HIGH_SEVERITIES
            and "known_bad_hash" in _event_markers(event)
        ):
            return True
    return False


def _ensure_family_diagnostics(
    recommendations: list[dict[str, object]],
    events: list[EventRecord],
) -> None:
    families = _families(events)
    existing = {
        str(item.get("registry_action_type"))
        for item in recommendations
        if item.get("registry_action_type")
    }

    def add(action_type: str, title: str, description: str) -> None:
        if action_type not in existing:
            recommendations.append(_controlled_diagnostic(action_type, title, description))
            existing.add(action_type)

    if families - {"demo"}:
        add(
            "collect_host_diagnostic",
            "Collect bounded host diagnostic",
            "Collect read-only platform, uptime, load and Response-agent state context.",
        )
    if families & {"execution", "privilege"}:
        add(
            "collect_process_diagnostic",
            "Collect bounded process diagnostic",
            "Collect a bounded process snapshot and endpoint-issued process handles without accepting a server-supplied PID.",
        )
    if families & {"malware", "file_integrity"}:
        add(
            "collect_file_diagnostic",
            "Collect bounded managed-file diagnostic",
            "Enumerate only regular files inside configured Response-agent managed roots and issue short-lived local file handles.",
        )
    if "network" in families:
        add(
            "collect_network_diagnostic",
            "Collect bounded network diagnostic",
            "On Linux, inspect bounded /proc network state directly without a shell or server-supplied network target.",
        )


def recommendations_for(events: list[EventRecord]) -> list[dict[str, object]]:
    """Preserve broad read-only investigation while requiring strong mutation evidence."""
    recommendations = list(base_recommendations_for(events))
    _ensure_family_diagnostics(recommendations, events)
    allow_process_termination = _process_termination_justified(events)
    allow_file_quarantine = _file_quarantine_justified(events)

    filtered: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for recommendation in recommendations:
        action_type = recommendation.get("registry_action_type")
        if action_type == "terminate_process_by_handle" and not allow_process_termination:
            continue
        if action_type in {
            "quarantine_artifact_by_handle",
            "restore_quarantined_artifact_by_handle",
        } and not allow_file_quarantine:
            continue
        key = (
            str(recommendation.get("action_type") or ""),
            str(recommendation.get("title") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        filtered.append(recommendation)
    return filtered


__all__ = ["probable_cause_for", "recommendations_for"]
