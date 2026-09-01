from __future__ import annotations

from app.database.models import EventRecord


def _action(
    action_type: str,
    title: str,
    description: str,
    *,
    registry_action_type: str | None = None,
) -> dict[str, object]:
    diagnostic = action_type == "diagnostic"
    controlled = registry_action_type is not None
    return {
        "action_type": action_type,
        "title": title,
        "description": description,
        "enabled": diagnostic or controlled,
        "phase": (
            "v1.1 — approval required"
            if controlled
            else "v1.1"
            if diagnostic
            else "v1.1 — not enabled"
        ),
        "registry_action_type": registry_action_type,
        "requires_approval": controlled,
    }


def _host_diagnostic() -> dict[str, object]:
    return _action(
        "diagnostic",
        "Collect bounded host diagnostic",
        "Collect OS, uptime, CPU-count, load, and Response-agent state-volume capacity without executing shell commands.",
        registry_action_type="collect_host_diagnostic",
    )


def _process_diagnostic() -> dict[str, object]:
    return _action(
        "diagnostic",
        "Collect bounded process diagnostic",
        "Collect a limited process inventory using native OS interfaces. Command lines and arbitrary process targeting are excluded.",
        registry_action_type="collect_process_diagnostic",
    )


def _network_diagnostic() -> dict[str, object]:
    return _action(
        "diagnostic",
        "Collect privacy-preserving network diagnostic",
        "On Linux, collect a bounded socket snapshot while pseudonymizing remote addresses on the endpoint before the result is returned.",
        registry_action_type="collect_network_diagnostic",
    )


def recommendations_for(events: list[EventRecord]) -> list[dict[str, object]]:
    categories = {str(event.category or "").lower() for event in events}
    types = {str(event.event_type or "").lower() for event in events}
    recommendations: list[dict[str, object]] = []
    demo_event = any(
        value in {"quietward_demo_service_unhealthy", "demo_service_unhealthy"}
        for value in types
    )

    # Keep the synthetic demo incident focused on its dedicated fixture. Real
    # incident families get the bounded, parameterless host diagnostic.
    if not demo_event:
        recommendations.append(_host_diagnostic())

    if demo_event:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Confirm demo service health",
                    "Verify the dedicated QuietWard Response demo service is the affected fixture and inspect its local health state.",
                ),
                _action(
                    "remediation",
                    "Restart QuietWard demo service",
                    "Restart only the dedicated QuietWard Response demo fixture after analyst approval and policy validation.",
                    registry_action_type="restart_quietward_demo_service",
                ),
            ]
        )

    process_relevant = bool(
        categories & {"execution", "malware", "persistence", "privilege", "process", "security"}
        or any(
            marker in event_type
            for event_type in types
            for marker in (
                "process",
                "malware",
                "ransomware",
                "credential",
                "persistence",
                "privilege",
                "injection",
                "shell",
            )
        )
    )
    network_relevant = bool(
        "network" in categories
        or any(
            marker in event_type
            for event_type in types
            for marker in ("network", "connection", "listener", "beacon", "c2")
        )
    )
    if process_relevant:
        recommendations.append(_process_diagnostic())
    if network_relevant:
        recommendations.extend([_process_diagnostic(), _network_diagnostic()])

    if "persistence" in categories or any("scheduled_task" in value for value in types):
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Inspect executable metadata",
                    "Verify the executable path, signer, ownership, timestamps, and expected deployment source.",
                ),
                _action(
                    "diagnostic",
                    "Calculate and verify hashes",
                    "Compare cryptographic hashes with approved software inventory and trusted intelligence.",
                ),
                _action(
                    "remediation",
                    "Disable persistence mechanism",
                    "General persistence changes remain intentionally unavailable in this diagnostic release.",
                ),
                _action(
                    "remediation",
                    "Quarantine executable",
                    "File quarantine remains intentionally unavailable in this diagnostic release.",
                ),
            ]
        )

    if network_relevant:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Inspect listener owner",
                    "Confirm which process owns the listener and whether the bind address and port are expected.",
                ),
                _action(
                    "diagnostic",
                    "Review recent connections",
                    "Review recent connection metadata associated with the listener and owning process.",
                ),
                _action(
                    "remediation",
                    "Restrict or stop the listener",
                    "Network and general service changes remain intentionally unavailable in this diagnostic release.",
                ),
            ]
        )

    # The dedicated demo health event is tagged operational for transport and UI
    # grouping, but it is not a resource-exhaustion incident. Keep its response card
    # focused instead of adding unrelated disk/capacity guidance.
    if not demo_event and (
        "operational" in categories
        or any("disk" in value or "service_unavailable" in value for value in types)
    ):
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Inspect capacity and service health",
                    "Confirm disk pressure, service state, and whether the condition is transient or sustained.",
                ),
                _action(
                    "remediation",
                    "Reclaim disk space",
                    "Deletion and cleanup actions remain intentionally unavailable in this diagnostic release.",
                ),
            ]
        )

    if len(recommendations) == 1:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Review supporting evidence",
                    "Inspect the incident timeline and supporting endpoint evidence before choosing a response.",
                ),
                _action(
                    "remediation",
                    "Apply corrective action",
                    "No general remediation action is enabled in this diagnostic release.",
                ),
            ]
        )

    unique: list[dict[str, object]] = []
    seen: set[tuple[object, object]] = set()
    for item in recommendations:
        key = (item["title"], item["registry_action_type"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def probable_cause_for(events: list[EventRecord]) -> str:
    categories = {str(event.category or "").lower() for event in events}
    types = {str(event.event_type or "").lower() for event in events}
    if any(
        value in {"quietward_demo_service_unhealthy", "demo_service_unhealthy"}
        for value in types
    ):
        return (
            "The dedicated QuietWard Response demo service reported an unhealthy state. "
            "The only enabled mutating remediation remains an approval-gated restart of that demo fixture."
        )
    if "persistence" in categories:
        return "One or more persistence-related changes were observed and correlated on the affected host."
    if "network" in categories:
        return "Network behavior on the affected host warrants investigation and correlation with the owning process."
    if "operational" in categories:
        return "The affected host reported an operational condition that may require investigation before corrective action."
    if "execution" in categories or "process" in categories:
        return "Process or execution behavior on the affected host warrants investigation before any response action."
    return "The available endpoint evidence was correlated into this incident, but the probable cause requires analyst review."
