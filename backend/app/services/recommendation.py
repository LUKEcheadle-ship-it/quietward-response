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
    if registry_action_type == "restart_quietward_demo_service":
        phase = "v1 — approval required"
    elif controlled:
        phase = "v1.1 — approval required"
    elif diagnostic:
        phase = "v1"
    else:
        phase = "v1.1 — not enabled"
    return {
        "action_type": action_type,
        "title": title,
        "description": description,
        "enabled": diagnostic or controlled,
        "phase": phase,
        "registry_action_type": registry_action_type,
        "requires_approval": controlled,
    }


def _controlled_diagnostic(
    title: str,
    description: str,
    registry_action_type: str,
) -> dict[str, object]:
    return _action(
        "diagnostic",
        title,
        description,
        registry_action_type=registry_action_type,
    )


def recommendations_for(events: list[EventRecord]) -> list[dict[str, object]]:
    categories = {str(event.category or "").lower() for event in events}
    types = {str(event.event_type or "").lower() for event in events}
    recommendations: list[dict[str, object]] = []

    demo_event = bool(
        types & {"quietward_demo_service_unhealthy", "demo_service_unhealthy"}
    )
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

    process_types = {"process_start", "privilege_escalation"}
    if types & process_types or "privilege" in categories:
        recommendations.append(
            _controlled_diagnostic(
                "Collect process and privilege context",
                "Return bounded read-only process and privilege evidence already observed by QuietWard.",
                "collect_process_diagnostic",
            )
        )

    file_types = {
        "malware_signature",
        "yara_match",
        "sensitive_file_change",
        "executable_created",
        "file_change",
    }
    if types & file_types or categories & {"file", "malware"}:
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect file and malware context",
                    "Return bounded read-only file-integrity, executable, malware-signature, and YARA evidence already observed by QuietWard.",
                    "collect_file_diagnostic",
                ),
                _action(
                    "remediation",
                    "Quarantine suspicious artifact",
                    "Artifact quarantine remains disabled until exact-path identity binding, rollback, and adversarial qualification are complete.",
                ),
            ]
        )

    persistence_types = {"persistence_change"}
    if types & persistence_types or "persistence" in categories or any(
        "scheduled_task" in value for value in types
    ):
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect persistence context",
                    "Return bounded persistence-change evidence already observed by QuietWard.",
                    "collect_persistence_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review related process context",
                    "Review nearby process evidence in the incident timeline. A process diagnostic is exposed only when process/privilege evidence is actually present.",
                ),
                _action(
                    "remediation",
                    "Disable persistence mechanism",
                    "Persistence modification remains disabled until each platform object type has an exact schema and rollback path.",
                ),
            ]
        )

    network_types = {"new_listening_port", "outbound_connection"}
    if types & network_types or "network" in categories or any(
        "listener" in value for value in types
    ):
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect network context",
                    "Return bounded listener and outbound-connection evidence already observed by QuietWard.",
                    "collect_network_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review owning-process context",
                    "Review nearby process evidence in the incident timeline. A process diagnostic is exposed only when process/privilege evidence is actually present.",
                ),
                _action(
                    "remediation",
                    "Block suspicious network activity",
                    "Firewall and host-isolation changes remain disabled until bounded rules, rollback, and connectivity-preservation checks are qualified.",
                ),
            ]
        )

    container_types = {
        "container_escape_indicator",
        "container_change",
        "container_configuration_change",
    }
    if types & container_types or "container" in categories:
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect container security context",
                    "Return bounded container security and configuration-change evidence already observed by QuietWard.",
                    "collect_container_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review related network context",
                    "Review nearby network evidence in the incident timeline. A network diagnostic is exposed only when network evidence is actually present.",
                ),
                _action(
                    "remediation",
                    "Contain suspicious container",
                    "Container stop/network containment remains disabled until exact container identity and rollback semantics are qualified.",
                ),
            ]
        )

    identity_types = {"auth_failure", "account_change", "privilege_escalation"}
    if types & identity_types or categories & {"identity", "privilege"}:
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect identity and authentication context",
                    "Return bounded authentication, account-change, and privilege-escalation evidence already observed by QuietWard.",
                    "collect_identity_diagnostic",
                ),
                _action(
                    "remediation",
                    "Revoke or lock compromised identity",
                    "Account/session mutation remains disabled until identity-provider-specific rollback and lockout safeguards are qualified.",
                ),
            ]
        )

    vulnerability_types = {"package_vulnerability", "configuration_weakness"}
    if types & vulnerability_types or categories & {"vulnerability", "configuration"}:
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect vulnerability and configuration context",
                    "Return bounded package-vulnerability and configuration-weakness evidence already observed by QuietWard.",
                    "collect_vulnerability_diagnostic",
                ),
                _action(
                    "remediation",
                    "Patch or harden affected component",
                    "Package/configuration mutation remains disabled until package-manager-specific preconditions and rollback are qualified.",
                ),
            ]
        )

    integrity_types = {
        "self_integrity_change",
        "evidence_integrity_failure",
        "collector_health",
    }
    if types & integrity_types or "integrity" in categories:
        recommendations.extend(
            [
                _controlled_diagnostic(
                    "Collect QuietWard integrity context",
                    "Return bounded self-integrity, evidence-chain, and collector-health evidence before trusting additional endpoint observations.",
                    "collect_integrity_diagnostic",
                ),
                _action(
                    "remediation",
                    "Revoke suspected endpoint credential",
                    "Agent disable/revocation is available to the analyst control plane; automatic revocation remains disabled pending stronger analyst identity/RBAC.",
                ),
            ]
        )

    if not demo_event and (
        "operational" in categories
        or any("disk" in value or "service_unavailable" in value for value in types)
    ):
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Assess service and resource health",
                    "Review health checks, storage pressure, dependency failures, and any existing process evidence around the incident window.",
                ),
                _action(
                    "remediation",
                    "Reclaim resources or restart affected service",
                    "General deletion, cleanup, and service-control actions are not enabled in this expansion.",
                ),
            ]
        )

    if not recommendations:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Validate the original evidence",
                    "Confirm the reporting source, timestamps, and affected host context.",
                ),
                _action(
                    "diagnostic",
                    "Review adjacent activity",
                    "Inspect related events before and after this observation.",
                ),
                _action(
                    "remediation",
                    "Apply corrective action",
                    "No generic remediation action is enabled; add a narrow typed responder for this incident class before execution.",
                ),
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
    categories = {str(event.category or "").lower() for event in events}
    types = {str(event.event_type or "").lower() for event in events}
    if types & {"quietward_demo_service_unhealthy", "demo_service_unhealthy"}:
        return (
            "The dedicated QuietWard Response demo service reported an unhealthy state. "
            "The approval-gated demo-fixture restart remains available."
        )
    if types & {"malware_signature", "yara_match"}:
        return (
            "QuietWard observed malware-signature or YARA evidence. File and process context "
            "should be collected before any containment decision."
        )
    if types & {"container_escape_indicator"}:
        return (
            "QuietWard observed a container escape indicator. Treat the container and host as "
            "potentially compromised until container, process, and network context are reviewed."
        )
    if "persistence" in categories or "persistence_change" in types:
        return (
            "A persistence mechanism changed and may be related to nearby execution or network "
            "activity. Analyst validation is required."
        )
    if "network" in categories or types & {"new_listening_port", "outbound_connection"}:
        return (
            "Unexpected network exposure or outbound activity was observed. Ownership, process "
            "context, and destination/listener scope should be validated."
        )
    if types & {"auth_failure", "account_change", "privilege_escalation"}:
        return (
            "Identity or privilege activity deviated from the expected baseline. Authentication, "
            "account, and process context should be reviewed before containment."
        )
    if types & {"package_vulnerability", "configuration_weakness"}:
        return (
            "A vulnerable package or security-relevant configuration weakness was observed. "
            "Confirm the affected component and exposure before applying changes."
        )
    if types & {"self_integrity_change", "evidence_integrity_failure"} or "integrity" in categories:
        return (
            "QuietWard or its evidence chain reported an integrity problem. Treat subsequent "
            "endpoint evidence cautiously until integrity context is reviewed."
        )
    if "operational" in categories:
        return (
            "Operational degradation may be related to resource pressure or a security event. "
            "Correlate process and adjacent event context before remediation."
        )
    return (
        "The available evidence is correlated by host, time, and shared indicators; "
        "a human assessment is still required."
    )
