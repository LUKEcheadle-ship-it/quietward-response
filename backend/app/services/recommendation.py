from __future__ import annotations

from app.database.models import EventRecord


def _action(action_type: str, title: str, description: str) -> dict[str, object]:
    diagnostic = action_type == "diagnostic"
    return {
        "action_type": action_type,
        "title": title,
        "description": description,
        "enabled": diagnostic,
        "phase": "Phase 1" if diagnostic else "Phase 2 — not enabled",
    }


def recommendations_for(events: list[EventRecord]) -> list[dict[str, object]]:
    categories = {event.category for event in events}
    types = {event.event_type for event in events}
    recommendations: list[dict[str, object]] = []

    if "persistence" in categories or any("scheduled_task" in value for value in types):
        recommendations.extend(
            [
                _action("diagnostic", "Inspect executable metadata", "Verify the executable path, signer, ownership, timestamps, and expected deployment source."),
                _action("diagnostic", "Calculate and verify hashes", "Compare cryptographic hashes with approved software inventory and trusted intelligence."),
                _action("diagnostic", "Inspect persistence entry", "Review the task, service, or startup entry and the account that created it."),
                _action("diagnostic", "Trace process ancestry", "Inspect the parent process and related launches around the first observation."),
                _action("diagnostic", "Review related network activity", "Correlate destinations and connection timing with the executable lifecycle."),
                _action("remediation", "Disable persistence mechanism", "Policy approval and endpoint execution are intentionally unavailable in Phase 1."),
                _action("remediation", "Quarantine executable", "File quarantine is intentionally unavailable in Phase 1."),
            ]
        )

    if "network" in categories or any("listener" in value for value in types):
        recommendations.extend(
            [
                _action("diagnostic", "Identify the owning process", "Map the socket to its process, service, image path, and execution account."),
                _action("diagnostic", "Inspect service configuration", "Review service arguments, dependencies, startup mode, and recent configuration changes."),
                _action("diagnostic", "Confirm bind scope", "Determine whether the listener is loopback, interface-specific, or wildcard-bound."),
                _action("remediation", "Restrict or stop the listener", "Network and service changes require Phase 2 policy and approval controls."),
            ]
        )

    if "operational" in categories or any("disk" in value or "service_unavailable" in value for value in types):
        recommendations.extend(
            [
                _action("diagnostic", "Identify largest consumers", "Measure filesystem usage and locate the largest recent contributors."),
                _action("diagnostic", "Inspect recent growth", "Compare file, database, and log growth over the incident window."),
                _action("diagnostic", "Assess service health", "Review health checks and dependency failures caused by resource exhaustion."),
                _action("remediation", "Reclaim disk space", "Deletion and cleanup actions are intentionally unavailable in Phase 1."),
            ]
        )

    if not recommendations:
        recommendations.extend(
            [
                _action("diagnostic", "Validate the original evidence", "Confirm the reporting source, timestamps, and affected host context."),
                _action("diagnostic", "Review adjacent activity", "Inspect related events before and after this observation."),
                _action("remediation", "Apply corrective action", "Remediation remains policy-gated and unavailable in Phase 1."),
            ]
        )

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, object]] = []
    for action in recommendations:
        key = (str(action["action_type"]), str(action["title"]))
        if key not in seen:
            unique.append(action)
            seen.add(key)
    return unique


def probable_cause_for(events: list[EventRecord]) -> str:
    categories = {event.category for event in events}
    if "persistence" in categories:
        return "A newly observed executable appears related to a persistence mechanism and subsequent execution or network activity. Analyst validation is required."
    if "network" in categories:
        return "A service appears to be listening beyond its expected exposure boundary. Ownership and configuration should be validated."
    if "operational" in categories:
        return "Resource growth appears temporally related to service degradation. Capacity, logs, and dependencies should be reviewed."
    return "The available evidence is correlated by host, time, and shared indicators; a human assessment is still required."
