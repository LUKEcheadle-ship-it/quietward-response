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
SHORT_HANDLE_TTL_ACTIONS = {
    "terminate_process_by_handle",
    "quarantine_artifact_by_handle",
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


def _verify_trusted_checkpoint_startup() -> None:
    config = (BACKEND / "app" / "config.py").read_text(encoding="utf-8")
    main = (BACKEND / "app" / "main.py").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for fragment in (
        "trusted_audit_checkpoint_path",
        "QWR_TRUSTED_AUDIT_CHECKPOINT_PATH must be absolute",
    ):
        if fragment not in config:
            raise RuntimeError(f"trusted checkpoint configuration missing: {fragment}")
    for fragment in (
        "_load_trusted_audit_checkpoint",
        "verify_audit_checkpoint",
        "trusted audit checkpoint verification failed at startup",
        "trusted audit checkpoint is missing, unreadable, or invalid JSON",
    ):
        if fragment not in main:
            raise RuntimeError(f"trusted checkpoint startup enforcement missing: {fragment}")
    if "QWR_TRUSTED_AUDIT_CHECKPOINT_PATH" not in env_example:
        raise RuntimeError("trusted checkpoint deployment setting is missing from .env.example")


def _verify_trusted_handle_ui() -> None:
    text = (
        ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx"
    ).read_text(encoding="utf-8")
    agents = (
        ROOT / "frontend" / "src" / "app" / "agents" / "page.tsx"
    ).read_text(encoding="utf-8")
    for fragment in (
        "handleOptionsFor",
        "Only handles returned by this incident and selected agent are offered",
        "Raw PIDs and file paths cannot be entered",
        "Run the matching diagnostic/action first",
        "agentCapabilityFresh",
        "CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000",
        "agentEnablesAction",
        "No affected Response agent has signed this action as enabled",
    ):
        if fragment not in text:
            raise RuntimeError(f"trusted handle/capability selector contract missing: {fragment}")
    if 'placeholder="qwrh1_' in text:
        raise RuntimeError("free-form opaque-handle input returned to the analyst UI")
    for fragment in (
        'type CapabilityStatus = "Fresh" | "Stale" | "Never reported"',
        "Run the official Response-agent poll path to refresh before response actions",
    ):
        if fragment not in agents:
            raise RuntimeError(f"agent capability freshness UI missing: {fragment}")


def _verify_agent_capability_negotiation() -> None:
    model = (BACKEND / "app" / "database" / "models.py").read_text(encoding="utf-8")
    schema = (BACKEND / "app" / "schemas" / "agent.py").read_text(encoding="utf-8")
    api = (BACKEND / "app" / "api" / "agents.py").read_text(encoding="utf-8")
    actions_api = (BACKEND / "app" / "api" / "actions.py").read_text(encoding="utf-8")
    policy = (BACKEND / "app" / "services" / "policy_service.py").read_text(encoding="utf-8")
    analyst_auth = (BACKEND / "app" / "services" / "analyst_auth.py").read_text(encoding="utf-8")
    migration = BACKEND / "alembic" / "versions" / "0003_agent_capabilities.py"
    enrollment = (ROOT / "scripts" / "enroll_response_agent.py").read_text(encoding="utf-8")
    poller = (ROOT / "scripts" / "poll_response_agent.py").read_text(encoding="utf-8")
    capability_helper = (ROOT / "scripts" / "response_agent_capabilities.py").read_text(
        encoding="utf-8"
    )

    if not migration.exists():
        raise RuntimeError("agent capability migration is missing")
    for fragment in ("supported_actions", "enabled_actions", "capabilities_updated_at"):
        if fragment not in model or fragment not in schema:
            raise RuntimeError(f"agent capability persistence/schema missing: {fragment}")
    for fragment in (
        '@router.post("/{agent_id}/capabilities"',
        "verify_agent_request",
        "allow_disabled=False",
        "unknown_agent_capability",
        "arbitrary_command_execution",
    ):
        if fragment not in api:
            raise RuntimeError(f"signed agent capability endpoint missing: {fragment}")
    if "_reject_unavailable_registered_capability" not in actions_api:
        raise RuntimeError("action creation does not preflight signed endpoint capability")
    for fragment in (
        "AGENT_CAPABILITY_MISSING_REASON",
        "AGENT_CAPABILITY_DISABLED_REASON",
        "AGENT_CAPABILITY_STALE_REASON",
        "_CAPABILITY_REPORT_MAX_AGE = timedelta(minutes=15)",
        "capabilities_updated_at",
        "enabled_actions",
    ):
        if fragment not in policy:
            raise RuntimeError(f"agent capability policy gate missing: {fragment}")
    if "_CAPABILITIES_RE" not in analyst_auth:
        raise RuntimeError("capability report is not classified as a machine-auth endpoint")
    if "sync_capabilities" not in enrollment or "sync_capabilities" not in poller:
        raise RuntimeError("official enrollment/poll path does not refresh signed capabilities")
    for fragment in (
        '"arbitrary_command_execution": False',
        '"resource_handle_protocol": "qwrh1"',
        "enabled_actions",
    ):
        if fragment not in capability_helper:
            raise RuntimeError(f"capability attestation helper missing: {fragment}")


def _verify_agent_key_rotation() -> None:
    model = (BACKEND / "app" / "database" / "models.py").read_text(encoding="utf-8")
    migration = (BACKEND / "alembic" / "versions" / "0003_agent_capabilities.py").read_text(
        encoding="utf-8"
    )
    agent_auth = (BACKEND / "app" / "services" / "agent_auth.py").read_text(encoding="utf-8")
    agent_api = (BACKEND / "app" / "api" / "agents.py").read_text(encoding="utf-8")
    analyst_auth = (BACKEND / "app" / "services" / "analyst_auth.py").read_text(
        encoding="utf-8"
    )
    helper = (ROOT / "scripts" / "rotate_response_agent_key.py").read_text(encoding="utf-8")

    for fragment in (
        "pending_key_id",
        "pending_hmac_key_b64",
        "pending_key_expires_at",
        "previous_key_id",
        "previous_hmac_key_b64",
        "previous_key_expires_at",
    ):
        if fragment not in model or fragment not in migration:
            raise RuntimeError(f"two-phase key-rotation persistence missing: {fragment}")
    for fragment in (
        "DEFAULT_PENDING_KEY_SECONDS = 300",
        "prepare_agent_key_rotation",
        "activate_pending_agent_key",
        "verify_pending_agent_request",
        "allow_previous_key: bool = False",
        "agent.previous_hmac_key_b64 = None",
        "agent.previous_key_expires_at = now",
        "invalid_pending_key",
    ):
        if fragment not in agent_auth:
            raise RuntimeError(f"immediate-revocation key-rotation hardening missing: {fragment}")
    for fragment in (
        '@router.post("/{agent_id}/rotate-key"',
        '@router.post("/{agent_id}/activate-key"',
        'action="agent_key_rotation_prepared"',
        'action="agent_key_rotated"',
        '"previous_key_revoked_at"',
        '"pending_key_rotation_exists"',
        "activate or recover the existing pending agent key before preparing another rotation",
        'response.headers["Pragma"] = "no-cache"',
    ):
        if fragment not in agent_api:
            raise RuntimeError(f"agent key-rotation API contract missing: {fragment}")
    if "_ROTATE_KEY_RE" not in analyst_auth or "_ACTIVATE_KEY_RE" not in analyst_auth:
        raise RuntimeError("agent key prepare/activate routes are not machine-auth classified")
    for fragment in (
        "--recover-next",
        'path.name + ".next"',
        "write_agent_config(next_path, rotated, force=False)",
        "_activate(rotated_agent)",
        "sync_capabilities(rotated_agent)",
        "os.replace(next_path, path)",
        "previous_key_revoked_at",
        "The new agent secret was not printed.",
    ):
        if fragment not in helper:
            raise RuntimeError(f"crash-recoverable local key-rotation helper missing: {fragment}")
    if "previous_key_expires_at" in helper:
        raise RuntimeError("rotation helper still expects the removed old-key grace response field")


def _verify_integrity_trust_freeze() -> None:
    policy = (BACKEND / "app" / "services" / "policy_service.py").read_text(encoding="utf-8")
    for fragment in (
        "INTEGRITY_TRUST_REASON",
        "incident_integrity_compromised",
        'definition.risk_level in {"medium", "high", "critical"}',
        '"evidence_integrity_failure"',
        '"self_integrity_change"',
    ):
        if fragment not in policy:
            raise RuntimeError(f"integrity trust freeze missing: {fragment}")


def _verify_sensitive_redaction() -> None:
    redaction = (BACKEND / "app" / "services" / "redaction.py").read_text(encoding="utf-8")
    ingestion = (BACKEND / "app" / "services" / "ingestion.py").read_text(encoding="utf-8")
    action_schema = (BACKEND / "app" / "schemas" / "action.py").read_text(encoding="utf-8")
    for fragment in (
        'REDACTED = "[REDACTED]"',
        '"authorization"',
        '"client_secret"',
        '"access_token"',
        '"refresh_token"',
        '"private_key"',
        "_MAX_REDACTION_DEPTH = 20",
        "redact_sensitive_text",
        "redact_sensitive",
    ):
        if fragment not in redaction:
            raise RuntimeError(f"credential redaction surface missing: {fragment}")
    for fragment in (
        "redact_sensitive(dumped)",
        "redact_sensitive_text",
        "payload=redacted_payload",
    ):
        if fragment not in ingestion:
            raise RuntimeError(f"event redaction-before-persistence missing: {fragment}")
    for fragment in (
        '@field_validator("result", "evidence", mode="before")',
        "redact_credential_fields",
        "redact_error_credentials",
        "redact_reason_credentials",
    ):
        if fragment not in action_schema:
            raise RuntimeError(f"action/approval credential redaction missing: {fragment}")


def main() -> int:
    actual = set(ACTION_REGISTRY)
    if actual != EXPECTED_ACTIONS:
        raise RuntimeError(f"unexpected v1.2 action registry: {sorted(actual)}")

    for action_type, definition in ACTION_REGISTRY.items():
        if not definition.approval_required:
            raise RuntimeError(f"action unexpectedly bypasses approval: {action_type}")
        if definition.parameter_mode == "resource_handle":
            if definition.validate_parameters({"pid": 1234}) == []:
                raise RuntimeError(f"raw PID unexpectedly accepted: {action_type}")
            if definition.validate_parameters({"path": "/tmp/a"}) == []:
                raise RuntimeError(f"raw path unexpectedly accepted: {action_type}")
        if action_type in SHORT_HANDLE_TTL_ACTIONS and definition.max_ttl_seconds > 240:
            raise RuntimeError(f"containment action TTL is too long: {action_type}")
    rollback = ACTION_REGISTRY["restore_quarantined_artifact_by_handle"]
    if rollback.max_ttl_seconds > 600:
        raise RuntimeError("rollback action TTL exceeds its bounded v1.2 window")

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
    _verify_trusted_checkpoint_startup()
    _verify_trusted_handle_ui()
    _verify_agent_capability_negotiation()
    _verify_agent_key_rotation()
    _verify_integrity_trust_freeze()
    _verify_sensitive_redaction()

    print("V1.2 RESPONSE SURFACE: PASS")
    print("registered_actions=", len(EXPECTED_ACTIONS))
    print("containment_action_ttl_max_seconds=240")
    print("rollback_action_ttl_max_seconds=600")
    print("legacy_policy_binding=fail-closed")
    print("generic_command_surface=absent")
    print("trusted_handle_selector=present")
    print("signed_agent_capability_negotiation=fresh-and-required")
    print("two_phase_agent_key_rotation=single-flight-immediate-old-key-revocation")
    print("integrity_compromise_mutation_freeze=present")
    print("credential_redaction_before_persistence=present")
    print("signed_audit_checkpoints=present")
    print("trusted_checkpoint_startup=present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
