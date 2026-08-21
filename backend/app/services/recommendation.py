from __future__ import annotations

from app.database.models import EventRecord


def _action(
    action_type: str,
    title: str,
    description: str,
    *,
    registry_action_type: str | None = None,
) -> dict[str, object]:
    controlled = registry_action_type is not None
    if registry_action_type == "restart_quietward_demo_service":
        phase = "v1 — approval required"
    elif controlled:
        phase = "v1.2 — approval required"
    elif action_type == "diagnostic":
        phase = "v1"
    else:
        phase = "v1 — not enabled"
    return {
        "action_type": action_type,
        "title": title,
        "description": description,
        "enabled": action_type == "diagnostic" or controlled,
        "phase": phase,
        "registry_action_type": registry_action_type,
        "requires_approval": controlled,
    }


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

    if types & {"process_start", "privilege_escalation"} or "privilege" in categories:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect bounded process diagnostic",
                    "Collect a bounded process snapshot. The Response agent issues short-lived opaque handles for non-protected process identities; it does not accept a server-supplied PID.",
                    registry_action_type="collect_process_diagnostic",
                ),
                _action(
                    "remediation",
                    "Terminate exact suspicious process by handle",
                    "Terminate only a non-protected process that still matches an unexpired agent-issued resource handle. The agent revalidates process identity immediately before termination.",
                    registry_action_type="terminate_process_by_handle",
                ),
            ]
        )

    if types & {
        "malware_signature",
        "yara_match",
        "sensitive_file_change",
        "executable_created",
        "file_change",
    } or categories & {"file", "malware"}:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect managed-file diagnostic",
                    "Enumerate only regular files inside explicitly configured Response-agent managed roots and issue short-lived opaque handles. No server-supplied path is accepted.",
                    registry_action_type="collect_file_diagnostic",
                ),
                _action(
                    "remediation",
                    "Quarantine exact artifact by handle",
                    "Move only the managed regular file represented by a current agent-issued handle into the private quarantine directory after identity revalidation.",
                    registry_action_type="quarantine_artifact_by_handle",
                ),
                _action(
                    "remediation",
                    "Restore quarantined artifact by rollback handle",
                    "Restore only a quarantine object represented by the rollback handle created by a prior quarantine execution; refuse restore when the original path is occupied or escapes the configured root.",
                    registry_action_type="restore_quarantined_artifact_by_handle",
                ),
            ]
        )

    if "persistence" in categories or "persistence_change" in types or any(
        "scheduled_task" in value for value in types
    ):
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host/agent health context without invoking a shell or service manager.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review persistence mechanism",
                    "Validate the exact task, service, startup entry, account, executable, creation time, fingerprint, and nearby execution/network evidence.",
                ),
                _action(
                    "remediation",
                    "Disable suspicious persistence",
                    "Persistence modification remains disabled until each object type has an exact handle-backed schema, preserved original state, and tested rollback path.",
                ),
            ]
        )

    if types & {"new_listening_port", "outbound_connection"} or "network" in categories or any(
        "listener" in value for value in types
    ):
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host/agent health context to pair with network evidence.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review network and owning-process context",
                    "Correlate listener or destination scope, protocol, port, owning process, first-seen time, and adjacent endpoint evidence.",
                ),
                _action(
                    "remediation",
                    "Contain suspicious network activity",
                    "Firewall and host-isolation changes remain disabled until bounded handle-backed rules, automatic expiry, rollback, and connectivity-preservation checks are qualified.",
                ),
            ]
        )

    if types & {
        "container_escape_indicator",
        "container_change",
        "container_configuration_change",
    } or "container" in categories:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host context before deciding whether container activity affected the host.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review container security context",
                    "Validate container identity, image, privileges, capabilities, mounts, namespaces, network activity, restart behavior, and security-fingerprint changes.",
                ),
                _action(
                    "remediation",
                    "Contain suspicious container",
                    "Container stop/network containment remains disabled until exact handle-backed container identity and recovery semantics are qualified.",
                ),
            ]
        )

    if types & {"auth_failure", "account_change", "privilege_escalation"} or categories & {
        "identity",
        "privilege",
    }:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host context to support authentication/privilege investigation.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review identity and authentication context",
                    "Correlate account identity, authentication failures, source context, privilege changes, session activity, and affected hosts while preserving available privacy controls.",
                ),
                _action(
                    "remediation",
                    "Revoke or lock compromised identity",
                    "Session revocation and temporary account lock remain disabled until provider-specific handle/identity binding, recovery, and stronger analyst-authentication controls are qualified.",
                ),
            ]
        )

    if types & {"package_vulnerability", "configuration_weakness"} or categories & {
        "vulnerability",
        "configuration",
    }:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host context before applying compensating controls or maintenance changes.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review vulnerable component and exposure",
                    "Confirm the affected package or configuration, installed version, severity, exposure path, compensating controls, and whether exploitation evidence exists.",
                ),
                _action(
                    "remediation",
                    "Patch or harden affected component",
                    "Package or configuration mutation remains disabled until platform-specific preconditions, maintenance-window handling, and rollback are qualified.",
                ),
            ]
        )

    if types & {
        "self_integrity_change",
        "evidence_integrity_failure",
        "collector_health",
    } or "integrity" in categories:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host and agent state before trusting further endpoint assertions.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Review sensor and evidence integrity",
                    "Validate evidence-chain state, sensor health, unexpected self-changes, collection gaps, and whether subsequent endpoint evidence should be treated as degraded trust.",
                ),
                _action(
                    "remediation",
                    "Revoke suspected sensor credential",
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
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host/agent health before classifying the incident as operational or adversarial.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Assess service and resource health",
                    "Review health checks, resource pressure, dependency failures, and nearby security events before classifying the incident as operational or adversarial.",
                ),
                _action(
                    "remediation",
                    "Restore affected service safely",
                    "General service control, cleanup, and deletion remain disabled; preserve evidence and define a narrow typed recovery action first.",
                ),
            ]
        )

    if not recommendations:
        recommendations.extend(
            [
                _action(
                    "diagnostic",
                    "Collect host diagnostic snapshot",
                    "Collect bounded read-only host/agent context without invoking arbitrary host commands.",
                    registry_action_type="collect_host_diagnostic",
                ),
                _action(
                    "diagnostic",
                    "Validate the original evidence",
                    "Confirm the reporting source, timestamps, affected host, event identity, confidence, and any linked indicators.",
                ),
                _action(
                    "diagnostic",
                    "Review adjacent activity",
                    "Inspect related events before and after the observation and determine whether a known response family applies.",
                ),
                _action(
                    "remediation",
                    "Define a bounded corrective action",
                    "No generic remediation action is enabled. Create a narrow typed responder only after the target, preconditions, rollback, and failure behavior are defined and tested.",
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
    if types & {"malware_signature", "yara_match"} or "malware" in categories:
        return (
            "Telemetry contains malware-signature or rule-match evidence. File identity, process "
            "ancestry, and related network activity should be validated before containment."
        )
    if "container" in categories or "container_escape_indicator" in types:
        return (
            "Telemetry indicates a container security change or possible escape condition. Treat "
            "the container and host as potentially compromised until correlated context is reviewed."
        )
    if "persistence" in categories or "persistence_change" in types:
        return (
            "A persistence mechanism changed and may be related to nearby execution or network "
            "activity. Validate the object and its creator before remediation."
        )
    if "network" in categories or types & {"new_listening_port", "outbound_connection"}:
        return (
            "Unexpected network exposure or outbound activity was observed. Ownership, process "
            "context, destination/listener scope, and timing should be validated."
        )
    if types & {"auth_failure", "account_change", "privilege_escalation"} or categories & {
        "identity",
        "privilege",
    }:
        return (
            "Identity or privilege activity deviated from the expected baseline. Authentication, "
            "account, session, and process context should be reviewed before containment."
        )
    if types & {"package_vulnerability", "configuration_weakness"} or categories & {
        "vulnerability",
        "configuration",
    }:
        return (
            "A vulnerable component or security-relevant configuration weakness was observed. "
            "Confirm exposure and exploitation evidence before applying changes."
        )
    if types & {"self_integrity_change", "evidence_integrity_failure"} or "integrity" in categories:
        return (
            "Sensor or evidence integrity is in question. Treat subsequent evidence cautiously "
            "until collection health and chain integrity are reviewed."
        )
    if "operational" in categories:
        return (
            "Operational degradation may be related to resource pressure or a security event. "
            "Correlate adjacent telemetry before remediation."
        )
    return (
        "The available evidence is correlated by host, time, and shared indicators; a human "
        "assessment is still required before containment or recovery."
    )
