from __future__ import annotations

from typing import Any

from app.database.models import EventRecord, IncidentRecord
from app.services.response_plan import build_response_plan as build_v11_response_plan


def _find_step(plan: dict[str, Any], section: str, step_id: str) -> dict[str, Any] | None:
    for step in plan.get(section, []):
        if isinstance(step, dict) and step.get("step_id") == step_id:
            return step
    return None


def _allowed_actions(incident: IncidentRecord) -> set[str]:
    allowed: set[str] = set()
    for item in list(incident.recommended_actions or []):
        if not isinstance(item, dict) or item.get("enabled") is not True:
            continue
        action_type = item.get("registry_action_type")
        if isinstance(action_type, str) and action_type:
            allowed.add(action_type)
    return allowed


def _enable_step(
    plan: dict[str, Any],
    allowed_actions: set[str],
    *,
    section: str,
    step_id: str,
    action_type: str,
    state: str = "available",
) -> None:
    step = _find_step(plan, section, step_id)
    if step is None or action_type not in allowed_actions:
        return
    step["state"] = state
    step["requires_approval"] = True
    step["executable_action_type"] = action_type
    actions = plan.setdefault("executable_actions", [])
    if action_type not in actions:
        actions.append(action_type)


def _append_step(
    plan: dict[str, Any],
    allowed_actions: set[str],
    *,
    section: str,
    step_id: str,
    title: str,
    description: str,
    action_type: str,
    destructive: bool,
) -> None:
    if action_type not in allowed_actions:
        return
    steps = plan.setdefault(section, [])
    if any(isinstance(step, dict) and step.get("step_id") == step_id for step in steps):
        return
    steps.append(
        {
            "step_id": step_id,
            "title": title,
            "description": description,
            "state": "available",
            "destructive": destructive,
            "requires_approval": True,
            "executable_action_type": action_type,
        }
    )
    actions = plan.setdefault("executable_actions", [])
    if action_type not in actions:
        actions.append(action_type)


def build_response_plan(
    incident: IncidentRecord,
    events: list[EventRecord],
) -> dict[str, object]:
    plan = build_v11_response_plan(incident, events)
    families = set(plan.get("attack_families", []))
    allowed_actions = _allowed_actions(incident)

    # Never advertise an executable action that the incident's persisted policy
    # recommendation set does not authorize. This keeps pre-v1.2 incidents fail-closed.
    plan["executable_actions"] = [
        item for item in plan.get("executable_actions", []) if item in allowed_actions
    ]
    for section in ("investigation_steps", "containment_steps", "recovery_steps"):
        for step in plan.get(section, []):
            action_type = step.get("executable_action_type") if isinstance(step, dict) else None
            if isinstance(action_type, str) and action_type not in allowed_actions:
                step["executable_action_type"] = None

    if families != {"demo"}:
        _append_step(
            plan,
            allowed_actions,
            section="investigation_steps",
            step_id="collect-host-diagnostic",
            title="Collect bounded host diagnostic",
            description=(
                "Use the Response-owned agent to collect platform, uptime, load and "
                "agent-state disk context. This action is read-only and accepts no target parameters."
            ),
            action_type="collect_host_diagnostic",
            destructive=False,
        )

    if families & {"execution", "privilege"}:
        _enable_step(
            plan,
            allowed_actions,
            section="investigation_steps",
            step_id="process-tree-review",
            action_type="collect_process_diagnostic",
        )
        _enable_step(
            plan,
            allowed_actions,
            section="containment_steps",
            step_id="stop-process",
            action_type="terminate_process_by_handle",
        )
        stop = _find_step(plan, "containment_steps", "stop-process")
        if stop is not None and stop.get("executable_action_type") == "terminate_process_by_handle":
            stop["description"] = (
                "Available only with an unexpired opaque process handle issued by a prior "
                "Response-agent process diagnostic for this incident. The agent revalidates "
                "process identity, protects critical/self processes, and never accepts a raw PID."
            )

    if families & {"malware", "file_integrity"}:
        _enable_step(
            plan,
            allowed_actions,
            section="investigation_steps",
            step_id="malware-file-identity",
            action_type="collect_file_diagnostic",
        )
        file_step = _find_step(plan, "investigation_steps", "malware-file-identity")
        if file_step is not None and file_step.get("executable_action_type") == "collect_file_diagnostic":
            file_step["description"] = (
                "Enumerate only regular files inside explicitly configured Response-agent "
                "managed roots and issue short-lived incident-bound opaque file handles; no raw server path is accepted."
            )
        _enable_step(
            plan,
            allowed_actions,
            section="containment_steps",
            step_id="quarantine-artifact",
            action_type="quarantine_artifact_by_handle",
        )
        quarantine = _find_step(plan, "containment_steps", "quarantine-artifact")
        if quarantine is not None and quarantine.get("executable_action_type") == "quarantine_artifact_by_handle":
            quarantine["description"] = (
                "Quarantine only the exact managed file represented by an unexpired incident-bound "
                "agent-issued handle after fingerprint/root revalidation. The result includes a separate rollback handle."
            )
        _append_step(
            plan,
            allowed_actions,
            section="recovery_steps",
            step_id="restore-quarantined-artifact",
            title="Restore quarantined artifact by rollback handle",
            description=(
                "Restore only through the incident-bound rollback handle created by a successful quarantine. "
                "The agent refuses restore if the original path is occupied or escapes its managed root."
            ),
            action_type="restore_quarantined_artifact_by_handle",
            destructive=False,
        )

    plan["schema_version"] = "1.1"
    plan["limitations"] = list(plan.get("limitations", [])) + [
        "v1.2 handle-bound containment is opt-in in each Response agent configuration.",
        "Process termination and file quarantine require a fresh incident-bound local diagnostic handle; raw PID/path targeting and cross-incident handle reuse remain unavailable.",
        "Pre-v1.2 incidents do not gain new executable actions retroactively unless their persisted recommendation set already authorizes them.",
        "Network/firewall, account/session, persistence, container, service, and package mutation remain non-executable pending equally narrow handle-backed executors.",
    ]
    return plan
