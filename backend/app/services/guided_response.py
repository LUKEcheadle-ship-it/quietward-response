from __future__ import annotations

from typing import Any, Iterable


_PRIORITY_RANK = {"routine": 0, "elevated": 1, "urgent": 2}
_STRENGTH_RANK = {"limited": 0, "corroborated": 1, "strong": 2}
_ALLOWED_PLAYBOOKS = {
    "malware_triage",
    "evidence_integrity_triage",
    "privilege_triage",
    "persistence_triage",
    "identity_triage",
    "network_triage",
    "container_triage",
    "vulnerability_triage",
    "process_execution_triage",
    "file_integrity_triage",
    "host_health_triage",
    "general_incident_triage",
}
_ALLOWED_HINTS = {
    "host_health",
    "process_inventory",
    "network_snapshot",
    "artifact_metadata_review",
    "identity_activity_review",
    "evidence_chain_review",
}


def _metadata(event: Any) -> dict[str, Any] | None:
    if str(getattr(event, "source", "") or "").casefold() != "quietward":
        return None
    payload = getattr(event, "payload", None)
    if not isinstance(payload, dict):
        return None
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return None
    if str(metadata.get("quietward_response_context_version") or "") != "1.1":
        return None
    # The contract is guidance-only. Refuse any payload that claims QuietWard has
    # executable authority so a malformed or downgraded event cannot influence the
    # response workflow as trusted guidance.
    if metadata.get("observation_only_source") is not True:
        return None
    if metadata.get("executable_authority") is not False:
        return None
    return metadata


def quietward_guidance(events: Iterable[Any]) -> dict[str, object] | None:
    """Return a validated aggregate QuietWard response profile for an incident.

    Only allowlisted coarse values from context v1.1 are consumed. Raw endpoint
    subjects, action targets, commands, paths, PIDs, and addresses are neither
    required nor trusted here.
    """
    profiles: list[dict[str, object]] = []
    for event in events:
        metadata = _metadata(event)
        if metadata is None:
            continue
        priority = str(metadata.get("response_priority") or "")
        strength = str(metadata.get("evidence_strength") or "")
        playbook = str(metadata.get("recommended_playbook") or "")
        if priority not in _PRIORITY_RANK:
            continue
        if strength not in _STRENGTH_RANK:
            continue
        if playbook not in _ALLOWED_PLAYBOOKS:
            continue
        raw_hints = metadata.get("investigation_hints")
        hints = []
        if isinstance(raw_hints, list):
            hints = [
                str(value)
                for value in raw_hints
                if isinstance(value, str) and value in _ALLOWED_HINTS
            ]
        profiles.append(
            {
                "priority": priority,
                "evidence_strength": strength,
                "recommended_playbook": playbook,
                "investigation_hints": hints,
            }
        )

    if not profiles:
        return None

    # Prefer the profile with the highest response priority, then strongest
    # evidence. The merged hint set still preserves useful corroborating context
    # from all accepted QuietWard events in the incident.
    selected = max(
        profiles,
        key=lambda item: (
            _PRIORITY_RANK[str(item["priority"])],
            _STRENGTH_RANK[str(item["evidence_strength"])],
        ),
    )
    merged_hints = sorted(
        {
            hint
            for profile in profiles
            for hint in profile["investigation_hints"]
            if isinstance(hint, str)
        }
    )
    return {
        "priority": selected["priority"],
        "evidence_strength": selected["evidence_strength"],
        "recommended_playbook": selected["recommended_playbook"],
        "investigation_hints": merged_hints,
        "source_event_count": len(profiles),
        "executable_authority": False,
    }
