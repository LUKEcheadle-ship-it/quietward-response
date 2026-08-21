#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.config import Settings
from app.services.action_registry import ACTION_REGISTRY
from app.services.response_plan_v12 import build_response_plan


EXPECTED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "terminate_process_by_handle",
    "collect_file_diagnostic",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
}


def _recommendation(action_type: str) -> dict[str, object]:
    return {
        "action_type": "remediation" if not action_type.startswith("collect_") else "diagnostic",
        "title": action_type,
        "description": action_type,
        "enabled": True,
        "phase": "v1.2 — approval required",
        "registry_action_type": action_type,
        "requires_approval": True,
    }


def _plan(event_type: str, category: str, allowed: set[str]):
    incident = SimpleNamespace(
        incident_id="surface-test",
        severity="high",
        recommended_actions=[_recommendation(item) for item in sorted(allowed)],
    )
    event = SimpleNamespace(event_type=event_type, category=category)
    return build_response_plan(incident, [event])


def _verify_checkpoint_surface() -> None:
    audit_api = (BACKEND / "app" / "api" / "audit.py").read_text(encoding="utf-8")
    audit_service = (BACKEND / "app" / "services" / "audit_service.py").read_text(
        encoding="utf-8"
    )
    analyst_auth = (BACKEND / "app" / "services" / "analyst_auth.py").read_text(
        encoding="utf-8"
    )
    required_api = (
        '@router.get("/checkpoint"',
        '@router.post("/checkpoint/verify"',
        "create_audit_checkpoint",
        "verify_audit_checkpoint",
    )
    missing = [fragment for fragment in required_api if fragment not in audit_api]
    if missing:
        raise RuntimeError(f"signed audit checkpoint API surface is incomplete: {missing}")
    for fragment in (
        "quietward-response-audit-checkpoint-v1",
        "checkpoint_prefix_hash_mismatch",
        "checkpoint_prefix_missing_or_truncated",
        "hmac.compare_digest",
    ):
        if fragment not in audit_service:
            raise RuntimeError(f"signed checkpoint hardening missing: {fragment}")
    if '_AUDIT_CHECKPOINT_VERIFY = "/api/v1/audit/checkpoint/verify"' not in analyst_auth:
        raise RuntimeError("checkpoint verification RBAC classification is missing")

    development = Settings(environment="development", api_host="127.0.0.1")
    if len(development.audit_checkpoint_secret) < 32:
        raise RuntimeError("audit checkpoint secret is below the configured minimum strength")


def _verify_trusted_handle_ui() -> None:
    text = (
        ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx"
    ).read_text(encoding="utf-8")
    for fragment in (
        "handleOptionsFor",
        "Only handles returned by this incident and selected agent are offered",
        "Raw PIDs and file paths cannot be entered",
        "Run the matching diagnostic/action first",
    ):
        if fragment not in text:
            raise RuntimeError(f"trusted handle selector contract missing: {fragment}")
    if 'placeholder="qwrh1_' in text:
        raise RuntimeError("free-form opaque-handle input returned to the analyst UI")


def main() -> int:
    actual = set(ACTION_REGISTRY)
    if actual != EXPECTED_ACTIONS:
        raise RuntimeError(f"unexpected v1.2 action registry: {sorted(actual)}")

    for action_type, definition in ACTION_REGISTRY.items():
        if not definition.approval_required:
            raise RuntimeError(f"action unexpectedly bypasses approval: {action_type}")
        if definition.parameter_mode == "resource_handle":
            if definition.max_ttl_seconds > 240:
                raise RuntimeError(f"handle action TTL is too long: {action_type}")
            if definition.validate_parameters({"pid": 1234}) == []:
                raise RuntimeError(f"raw PID unexpectedly accepted: {action_type}")
            if definition.validate_parameters({"path": "/tmp/a"}) == []:
                raise RuntimeError(f"raw path unexpectedly accepted: {action_type}")

    process_plan = _plan(
        "privilege_escalation",
        "privilege",
        {"collect_host_diagnostic", "collect_process_diagnostic", "terminate_process_by_handle"},
    )
    required_process = {
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "terminate_process_by_handle",
    }
    if not required_process.issubset(set(process_plan["executable_actions"])):
        raise RuntimeError(f"process plan missing v1.2 actions: {process_plan!r}")

    malware_plan = _plan(
        "ransomware_detected",
        "malware",
        {
            "collect_host_diagnostic",
            "collect_file_diagnostic",
            "quarantine_artifact_by_handle",
            "restore_quarantined_artifact_by_handle",
        },
    )
    required_file = {
        "collect_host_diagnostic",
        "collect_file_diagnostic",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
    }
    if not required_file.issubset(set(malware_plan["executable_actions"])):
        raise RuntimeError(f"malware plan missing v1.2 actions: {malware_plan!r}")

    legacy = _plan("malware_signature", "malware", set())
    if legacy["executable_actions"]:
        raise RuntimeError("legacy incident gained v1.2 executable actions retroactively")

    for forbidden in ("run_shell", "run_command", "powershell", "execute_script"):
        if forbidden in ACTION_REGISTRY:
            raise RuntimeError(f"generic execution surface detected: {forbidden}")

    _verify_checkpoint_surface()
    _verify_trusted_handle_ui()

    print("V1.2 RESPONSE SURFACE: PASS")
    print("registered_actions=", len(EXPECTED_ACTIONS))
    print("handle_actions_ttl_max_seconds=240")
    print("legacy_policy_binding=fail-closed")
    print("generic_command_surface=absent")
    print("trusted_handle_selector=present")
    print("signed_audit_checkpoints=present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
