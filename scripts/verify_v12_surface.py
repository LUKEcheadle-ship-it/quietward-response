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
    "collect_network_diagnostic",
    "terminate_process_by_handle",
    "collect_file_diagnostic",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _recommendation(action_type: str) -> dict[str, object]:
    return {
        "action_type": "diagnostic" if action_type.startswith("collect_") else "remediation",
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


def _verify_action_surface() -> None:
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
    for action_type in ("terminate_process_by_handle", "quarantine_artifact_by_handle"):
        if ACTION_REGISTRY[action_type].max_ttl_seconds > 240:
            raise RuntimeError(f"high-impact action TTL is too long: {action_type}")
    if ACTION_REGISTRY["restore_quarantined_artifact_by_handle"].max_ttl_seconds > 600:
        raise RuntimeError("rollback action TTL exceeds bounded v1.2 window")
    network = ACTION_REGISTRY["collect_network_diagnostic"]
    if network.risk_level != "low" or network.parameter_mode != "none":
        raise RuntimeError("network diagnostic must remain a parameter-free low-risk action")
    if network.supported_os != ("linux",):
        raise RuntimeError("network diagnostic must remain Linux-only until independently qualified elsewhere")


def _verify_response_plans() -> None:
    network_plan = _plan(
        "outbound_connection",
        "network",
        {"collect_host_diagnostic", "collect_network_diagnostic"},
    )
    required_network = {"collect_host_diagnostic", "collect_network_diagnostic"}
    if not required_network.issubset(set(network_plan["executable_actions"])):
        raise RuntimeError(f"network plan missing read-only diagnostics: {network_plan!r}")
    if any(
        item in set(network_plan["executable_actions"])
        for item in ("network_block", "isolate_host", "firewall_rule")
    ):
        raise RuntimeError("network plan exposed an unqualified mutating network action")

    process_plan = _plan(
        "privilege_escalation",
        "privilege",
        {"collect_host_diagnostic", "collect_process_diagnostic", "terminate_process_by_handle"},
    )
    if not {
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "terminate_process_by_handle",
    }.issubset(set(process_plan["executable_actions"])):
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
    if not {
        "collect_host_diagnostic",
        "collect_file_diagnostic",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
    }.issubset(set(malware_plan["executable_actions"])):
        raise RuntimeError(f"malware plan missing v1.2 actions: {malware_plan!r}")

    legacy = _plan("malware_signature", "malware", set())
    if legacy["executable_actions"]:
        raise RuntimeError("legacy incident gained v1.2 executable actions retroactively")


def _verify_network_agent_surface() -> None:
    network = _text(ROOT / "scripts" / "response_agent_network.py")
    v12_agent = _text(ROOT / "scripts" / "response_agent_v12.py")
    poller = _text(ROOT / "scripts" / "poll_response_agent.py")
    enrollment = _text(ROOT / "scripts" / "enroll_response_agent.py")
    rotation = _text(ROOT / "scripts" / "rotate_response_agent_key.py")
    for fragment in (
        "MAX_NETWORK_RESULTS = 256",
        "NETWORK_PRIVACY_KEY_BYTES = 32",
        'NETWORK_PRIVACY_KEY_FILENAME = "response-agent-network-privacy.bin"',
        '"raw_network_addresses_returned": False',
        '"remote_address_identity": "endpoint_local_hmac_sha256_128"',
        '"remote_address_hmac_sha256"',
        "hmac.new(",
        'kind="network_socket"',
        "collect_network_diagnostic",
        "network privacy key permissions are not private",
    ):
        if fragment not in network:
            raise RuntimeError(f"network diagnostic privacy/bounds contract missing: {fragment}")
    for forbidden in ("import subprocess", "subprocess.run", "subprocess.Popen", "os.system", "shell=True"):
        if forbidden in network:
            raise RuntimeError(f"network diagnostic gained command execution primitive: {forbidden}")
    for fragment in (
        'base._ACTION_PARAMETER_MODE.setdefault("collect_network_diagnostic", "none")',
        '"collect_network_diagnostic"',
        "collect_network_diagnostic(self.resources)",
    ):
        if fragment not in v12_agent:
            raise RuntimeError(f"v1.2 agent network integration missing: {fragment}")
    for label, text in (("poll", poller), ("enrollment", enrollment), ("rotation", rotation)):
        if "from response_agent_v12 import" not in text:
            raise RuntimeError(f"official {label} path bypasses canonical v1.2 agent")


def _verify_control_plane_hardening() -> None:
    model = _text(BACKEND / "app" / "database" / "models.py")
    migration = _text(BACKEND / "alembic" / "versions" / "0003_agent_capabilities.py")
    agents_api = _text(BACKEND / "app" / "api" / "agents.py")
    policy = _text(BACKEND / "app" / "services" / "policy_service.py")
    analyst_auth = _text(BACKEND / "app" / "services" / "analyst_auth.py")
    audit_service = _text(BACKEND / "app" / "services" / "audit_service.py")
    main = _text(BACKEND / "app" / "main.py")
    redaction = _text(BACKEND / "app" / "services" / "redaction.py")

    for fragment in (
        "supported_actions",
        "enabled_actions",
        "capabilities_updated_at",
        "pending_key_id",
        "pending_hmac_key_b64",
        "pending_key_expires_at",
        "previous_key_id",
        "previous_key_revoked_at",
    ):
        if fragment not in model or fragment not in migration:
            raise RuntimeError(f"agent trust/rotation persistence missing: {fragment}")
    for retired in ("previous_hmac_key_b64", "previous_key_expires_at"):
        if retired in model or retired in migration:
            raise RuntimeError(f"retired agent secret storage returned: {retired}")

    for fragment in (
        '@router.post("/{agent_id}/capabilities"',
        '@router.post("/{agent_id}/rotate-key"',
        '@router.post("/{agent_id}/activate-key"',
        "unknown_agent_capability",
        "pending_key_rotation_exists",
    ):
        if fragment not in agents_api:
            raise RuntimeError(f"agent trust API missing: {fragment}")
    for fragment in (
        "AGENT_CAPABILITY_STALE_REASON",
        "_CAPABILITY_REPORT_MAX_AGE = timedelta(minutes=15)",
        "INTEGRITY_TRUST_REASON",
        "incident_integrity_compromised",
    ):
        if fragment not in policy:
            raise RuntimeError(f"policy hardening missing: {fragment}")
    for fragment in ("_CAPABILITIES_RE", "_ROTATE_KEY_RE", "_ACTIVATE_KEY_RE"):
        if fragment not in analyst_auth:
            raise RuntimeError(f"machine-auth route classification missing: {fragment}")

    for fragment in (
        "quietward-response-audit-checkpoint-v1",
        "checkpoint_prefix_hash_mismatch",
        "checkpoint_prefix_missing_or_truncated",
        "hmac.compare_digest",
    ):
        if fragment not in audit_service:
            raise RuntimeError(f"signed checkpoint hardening missing: {fragment}")
    for fragment in (
        "_load_trusted_audit_checkpoint",
        "verify_audit_checkpoint",
        "trusted audit checkpoint verification failed at startup",
    ):
        if fragment not in main:
            raise RuntimeError(f"trusted checkpoint startup enforcement missing: {fragment}")
    for fragment in (
        'REDACTED = "[REDACTED]"',
        '"authorization"',
        '"access_token"',
        '"refresh_token"',
        '"private_key"',
    ):
        if fragment not in redaction:
            raise RuntimeError(f"sensitive redaction surface missing: {fragment}")

    settings = Settings(environment="development", api_host="127.0.0.1")
    if len(settings.audit_checkpoint_secret) < 32:
        raise RuntimeError("audit checkpoint secret minimum strength regressed")


def _verify_ui_boundaries() -> None:
    actions = _text(ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx")
    agents = _text(ROOT / "frontend" / "src" / "app" / "agents" / "page.tsx")
    for fragment in (
        "handleOptionsFor",
        "Only handles returned by this incident and selected agent are offered",
        "Raw PIDs and file paths cannot be entered",
        "agentCapabilityFresh",
        "CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000",
    ):
        if fragment not in actions:
            raise RuntimeError(f"trusted analyst action UI contract missing: {fragment}")
    if 'placeholder="qwrh1_' in actions:
        raise RuntimeError("free-form opaque-handle input returned to analyst UI")
    for fragment in ("Fresh", "Stale", "Never reported", "Response agents"):
        if fragment not in agents:
            raise RuntimeError(f"agent trust-state UI missing: {fragment}")


def main() -> int:
    _verify_action_surface()
    _verify_response_plans()
    _verify_network_agent_surface()
    _verify_control_plane_hardening()
    _verify_ui_boundaries()

    print("V1.2 RESPONSE SURFACE: PASS")
    print("registered_actions=8")
    print("linux_network_diagnostic=read-only/endpoint-keyed-pseudonymous")
    print("handle_containment=bounded")
    print("signed_agent_capability_negotiation=present")
    print("two_phase_agent_key_rotation=present")
    print("integrity_trust_freeze=present")
    print("signed_audit_checkpoints=present")
    print("trusted_handle_selector=present")
    print("generic_command_surface=absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
