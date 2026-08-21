from __future__ import annotations

from typing import Any

from app.database.models import EventRecord, IncidentRecord
from app.services.response_plan import build_response_plan as build_v11_response_plan


def _find_step(plan: dict[str, Any], section: str, step_id: str) -> dict[str, Any] | None:
    for step in plan.get(section, []):
        if isinstance(step, dict) and step.get("step_id") == step_id:
            return step
    return None


def _enable_step(
    plan: dict[str, Any],
    *,
    section: str,
    step_id: str,
    action_type: str,
    state: str = "available",
) -> None:
    step = _find_step(plan, section, step_id)
    if step is None:
        return
    step["state"] = state
    step["requires_approval"] = True
    step["executable_action_type"] = action_type
    actions = plan.setdefault("executable_actions", [])
    if action_type not in actions:
        actions.append(action_type)


def _append_step(
    plan: dict[str, Any],
    *,
    section: str,
    step_id: str,
    title: str,
    description: str,
    action_type: str,
    destructive: bool,
) -> None:
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

    # A bounded host snapshot is safe and useful across incident families. It does
    # not accept server-controlled targets or invoke shell commands.
    _append_step(
        plan,
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
            section="investigation_steps",
            step_id="process-tree-review",
            action_type="collect_process_diagnostic",
        )
        _enable_step(
            plan,
            section="containment_steps",
            step_id="stop-process",
            action_type="terminate_process_by_handle",
        )
        stop = _find_step(plan, "containment_steps", "stop-process")
        if stop is not None:
            stop["description"] = (
                "Available only with an unexpired opaque process handle issued by a prior "
                "Response-agent process diagnostic. The agent revalidates process identity, "
                "protects critical/self processes, and never accepts a raw PID."
            )

    if families & {"malware", "file_integrity"}:
        _enable_step(
            plan,
            section="investigation_steps",
            step_id="malware-file-identity",
            action_type="collect_file_diagnostic",
        )
        file_step = _find_step(plan, "investigation_steps", "malware-file-identity")
        if file_step is not None:
            file_step["description"] = (
                "Enumerate only regular files inside explicitly configured Response-agent "
                "managed roots and issue short-lived opaque file handles; no raw server path is accepted."
            )
        _enable_step(
            plan,
            section="containment_steps",
            step_id="quarantine-artifact",
            action_type="quarantine_artifact_by_handle",
        )
        quarantine = _find_step(plan, "containment_steps", "quarantine-artifact")
        if quarantine is not None:
            quarantine["description"] = (
                "Quarantine only the exact managed file represented by an unexpired agent-issued "
                "handle after fingerprint/root revalidation. The result includes a separate rollback handle."
            )
        _append_step(
            plan,
            section="recovery_steps",
            step_id="restore-quarantined-artifact",
            title="Restore quarantined artifact by rollback handle",
            description=(
                "Restore only through the rollback handle created by a successful quarantine. "
                "The agent refuses restore if the original path is occupied or escapes its managed root."
            ),
            action_type="restore_quarantined_artifact_by_handle",
            destructive=False,
        )

    plan["schema_version"] = "1.1"
    plan["limitations"] = list(plan.get("limitations", [])) + [
        "v1.2 handle-bound containment is opt-in in each Response agent configuration.",
        "Process termination and file quarantine require a fresh local diagnostic handle; raw PID/path targeting remains unavailable.",
        "Network/firewall, account/session, persistence, container, service, and package mutation remain non-executable pending equally narrow handle-backed executors.",
    ]
    return plan
