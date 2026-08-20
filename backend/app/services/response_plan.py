from __future__ import annotations

import hashlib
from collections.abc import Iterable

from app.database.models import EventRecord, IncidentRecord
from app.services.response_family import infer_response_family


def _step(
    step_id: str,
    title: str,
    description: str,
    state: str,
    *,
    destructive: bool = False,
    requires_approval: bool = False,
    executable_action_type: str | None = None,
) -> dict[str, object]:
    return {
        "step_id": step_id,
        "title": title,
        "description": description,
        "state": state,
        "destructive": destructive,
        "requires_approval": requires_approval,
        "executable_action_type": executable_action_type,
    }


def _dedupe_steps(steps: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    for step in steps:
        step_id = str(step["step_id"])
        if step_id not in seen:
            result.append(step)
            seen.add(step_id)
    return result


def _families(events: list[EventRecord]) -> list[str]:
    values = {
        infer_response_family(event.event_type, event.category)
        for event in events
    }
    return sorted(values or {"unknown"})


def _priority(incident: IncidentRecord, families: list[str]) -> str:
    severity = str(incident.severity or "").lower()
    if severity == "critical" or ("integrity" in families and severity == "high"):
        return "critical"
    if severity == "high" or set(families) & {"malware", "privilege", "container"}:
        return "high"
    if severity == "medium" or set(families) & {
        "identity",
        "persistence",
        "network",
        "vulnerability",
    }:
        return "elevated"
    return "routine"


def build_response_plan(
    incident: IncidentRecord,
    events: list[EventRecord],
) -> dict[str, object]:
    families = _families(events)
    investigation: list[dict[str, object]] = [
        _step(
            "validate-evidence",
            "Validate source evidence",
            "Confirm event identity, timestamps, sensor/source trust, affected hosts, confidence, and corroborating indicators in the incident timeline.",
            "available",
        ),
        _step(
            "scope-adjacent-events",
            "Scope adjacent activity",
            "Review events immediately before and after the trigger and identify additional hosts, accounts, processes, files, containers, or destinations that may belong to the same incident.",
            "available",
        ),
    ]
    containment: list[dict[str, object]] = []
    recovery: list[dict[str, object]] = []
    escalation: list[str] = []
    objectives = [
        "Preserve evidence and confirm the affected scope before making host changes.",
        "Contain verified malicious activity with the narrowest practical blast radius.",
        "Recover service only after persistence, identity, and integrity risks are addressed.",
        "Keep every analyst decision and controlled action auditable.",
    ]

    if "malware" in families or "file_integrity" in families:
        investigation.extend(
            [
                _step(
                    "malware-file-identity",
                    "Validate suspicious artifact identity",
                    "Review cryptographic hashes, signer or ownership metadata, scanner/rule evidence, creation or modification times, and related process ancestry.",
                    "available",
                ),
                _step(
                    "malware-network-correlation",
                    "Correlate artifact with network activity",
                    "Check whether the same executable or process context appears near unexpected listeners or outbound destinations.",
                    "available",
                ),
            ]
        )
        containment.append(
            _step(
                "quarantine-artifact",
                "Quarantine confirmed malicious artifact",
                "Planned capability: preserve evidence, bind to an exact artifact identity, move it to a controlled quarantine location, and record rollback metadata.",
                "planned",
                destructive=True,
                requires_approval=True,
            )
        )
        recovery.append(
            _step(
                "restore-clean-artifact",
                "Restore from trusted source",
                "Replace or repair the affected component only after confirming persistence and execution paths are removed and a trusted source is available.",
                "manual",
                requires_approval=True,
            )
        )
        escalation.append(
            "Escalate when malware evidence is confirmed on multiple hosts or reappears after cleanup."
        )

    if "execution" in families or "privilege" in families:
        investigation.append(
            _step(
                "process-tree-review",
                "Review process tree and privilege context",
                "Validate process identity, parent/child chain, execution account, privilege level, command metadata or hashes, and nearby persistence/network evidence.",
                "available",
            )
        )
        containment.append(
            _step(
                "stop-process",
                "Stop a confirmed malicious process",
                "Planned capability: target an exact process identity with stale-PID protection, bounded timeout, evidence capture, and explicit analyst approval.",
                "planned",
                destructive=True,
                requires_approval=True,
            )
        )
        escalation.append(
            "Escalate immediately when privilege escalation is confirmed or a privileged malicious process persists."
        )

    if "identity" in families:
        investigation.append(
            _step(
                "identity-review",
                "Review authentication and account activity",
                "Correlate authentication failures, account changes, sessions, source context, privilege changes, and affected hosts or services.",
                "available",
            )
        )
        containment.extend(
            [
                _step(
                    "revoke-sessions",
                    "Revoke compromised sessions",
                    "Planned provider-specific capability with exact identity binding, scope preview, recovery guidance, and analyst approval.",
                    "planned",
                    destructive=True,
                    requires_approval=True,
                ),
                _step(
                    "temporary-account-lock",
                    "Temporarily lock compromised account",
                    "Planned provider-specific capability with lockout safeguards, break-glass handling, and explicit recovery steps.",
                    "planned",
                    destructive=True,
                    requires_approval=True,
                ),
            ]
        )
        recovery.append(
            _step(
                "identity-recovery",
                "Rotate credentials and restore access",
                "After containment, rotate compromised credentials, validate MFA/recovery paths, review privilege membership, and restore access deliberately.",
                "manual",
                requires_approval=True,
            )
        )
        escalation.append(
            "Escalate when a privileged account, service account, or repeated multi-account attack is involved."
        )

    if "persistence" in families:
        investigation.append(
            _step(
                "persistence-review",
                "Inspect persistence object",
                "Validate the exact scheduled task, service, startup entry, account, executable, fingerprint, creation time, and associated execution evidence.",
                "available",
            )
        )
        containment.append(
            _step(
                "disable-persistence",
                "Disable confirmed malicious persistence",
                "Planned object-specific capability that preserves original state and requires a tested rollback path before execution.",
                "planned",
                destructive=True,
                requires_approval=True,
            )
        )
        recovery.append(
            _step(
                "persistence-recovery",
                "Verify persistence remains absent",
                "Re-scan the affected persistence surfaces after containment and after the next restart or service lifecycle event.",
                "manual",
            )
        )
        escalation.append(
            "Escalate when persistence recreates itself or is tied to privileged execution."
        )

    if "network" in families:
        investigation.append(
            _step(
                "network-review",
                "Review suspicious network activity",
                "Validate listener or destination scope, protocol, port, owning process, timing, recurrence, and related endpoint evidence.",
                "available",
            )
        )
        containment.extend(
            [
                _step(
                    "temporary-network-block",
                    "Apply temporary bounded network block",
                    "Planned capability with exact destination/port identity, expiry, connectivity-preservation checks, and rollback.",
                    "planned",
                    destructive=True,
                    requires_approval=True,
                ),
                _step(
                    "isolate-host",
                    "Isolate host when compromise is confirmed",
                    "Future high-impact capability requiring a management-path exception, automatic expiry, rollback, and independent adversarial qualification.",
                    "blocked",
                    destructive=True,
                    requires_approval=True,
                ),
            ]
        )
        recovery.append(
            _step(
                "network-recovery",
                "Restore connectivity deliberately",
                "Remove temporary blocks only after the owning process or underlying compromise has been addressed and monitoring confirms the activity has stopped.",
                "manual",
                requires_approval=True,
            )
        )

    if "container" in families:
        investigation.append(
            _step(
                "container-review",
                "Review container security posture",
                "Validate image identity, privileges, capabilities, mounts, namespaces, network mode, restart behavior, security fingerprint, and host-level activity.",
                "available",
            )
        )
        containment.append(
            _step(
                "stop-container",
                "Stop confirmed malicious container",
                "Planned capability with exact container identity, stale-target protection, evidence preservation, and documented recovery semantics.",
                "planned",
                destructive=True,
                requires_approval=True,
            )
        )
        recovery.append(
            _step(
                "recreate-container",
                "Recreate from trusted configuration",
                "Rebuild from a trusted image and configuration rather than resuming an untrusted container state.",
                "manual",
                requires_approval=True,
            )
        )
        escalation.append(
            "Escalate immediately for escape indicators, host namespace access, docker-socket access, or sensitive host mounts."
        )

    if "vulnerability" in families:
        investigation.append(
            _step(
                "vulnerability-review",
                "Validate vulnerability and exposure",
                "Confirm installed version/configuration, severity, reachable attack path, compensating controls, exploitability, and any exploitation evidence.",
                "available",
            )
        )
        containment.append(
            _step(
                "reduce-vulnerable-exposure",
                "Reduce vulnerable exposure",
                "Use a manual compensating control when practical until a platform-specific typed patch or configuration responder is qualified.",
                "manual",
                requires_approval=True,
            )
        )
        recovery.append(
            _step(
                "patch-and-verify",
                "Patch or harden and verify",
                "Apply the vendor or platform remediation in a maintenance window, verify the new state, and confirm the exposure is no longer detected.",
                "manual",
                requires_approval=True,
            )
        )

    if "integrity" in families:
        investigation.append(
            _step(
                "integrity-review",
                "Validate sensor and evidence integrity",
                "Review chain verification, sensor health, self-integrity changes, collection gaps, credential state, and whether later evidence should be treated as reduced trust.",
                "available",
            )
        )
        containment.append(
            _step(
                "disable-suspect-agent",
                "Disable suspected agent credential",
                "The analyst control plane can disable a known agent record. Automatic revocation is intentionally not performed in this alpha.",
                "manual",
                requires_approval=True,
            )
        )
        escalation.append(
            "Escalate any confirmed evidence-chain tamper or sensor compromise before relying on additional endpoint claims."
        )

    if "operational" in families:
        investigation.append(
            _step(
                "operational-review",
                "Separate operational failure from attack activity",
                "Review service health, resource pressure, dependency failures, and nearby security telemetry before applying corrective changes.",
                "available",
            )
        )
        recovery.append(
            _step(
                "operational-recovery",
                "Restore service using the normal owner procedure",
                "Preserve relevant evidence first, then use the service owner's documented recovery path rather than a generic remote command.",
                "manual",
            )
        )

    executable_actions: list[str] = []
    if "demo" in families:
        containment.append(
            _step(
                "restart-demo-fixture",
                "Reset dedicated demo fixture",
                "The released controlled-response demo action changes only the dedicated Response demo fixture and requires analyst approval plus deterministic policy validation.",
                "available",
                requires_approval=True,
                executable_action_type="restart_quietward_demo_service",
            )
        )
        executable_actions.append("restart_quietward_demo_service")

    if "unknown" in families:
        escalation.append(
            "Escalate when the event family cannot be mapped confidently to a bounded response procedure."
        )

    investigation = _dedupe_steps(investigation)
    containment = _dedupe_steps(containment)
    recovery = _dedupe_steps(recovery)
    escalation = list(dict.fromkeys(escalation))

    plan_key = "|".join([incident.incident_id, *families]).encode("utf-8")
    plan_id = "qwr-plan-" + hashlib.sha256(plan_key).hexdigest()[:20]

    return {
        "schema_version": "1.0",
        "plan_id": plan_id,
        "incident_id": incident.incident_id,
        "mode": "advisory_with_controlled_actions",
        "priority": _priority(incident, families),
        "attack_families": families,
        "objectives": objectives,
        "investigation_steps": investigation,
        "containment_steps": containment,
        "recovery_steps": recovery,
        "escalation_conditions": escalation,
        "executable_actions": executable_actions,
        "limitations": [
            "The alpha does not execute arbitrary shell, PowerShell, cmd, service-manager, package-manager, firewall, process-kill, file-quarantine, or account-management commands.",
            "Planned/manual steps are analyst guidance, not claims that endpoint automation exists.",
            "The only state-changing endpoint action qualified in this branch is the dedicated demo-fixture reset.",
            "Analyst identity remains development-grade X-Actor-ID until OIDC/RBAC is implemented.",
        ],
    }
