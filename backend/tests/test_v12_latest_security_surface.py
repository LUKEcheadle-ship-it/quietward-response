from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_latest_v12_security_controls_are_present_end_to_end() -> None:
    model = _text(BACKEND / "app" / "database" / "models.py")
    migration = _text(BACKEND / "alembic" / "versions" / "0003_agent_capabilities.py")
    agent_auth = _text(BACKEND / "app" / "services" / "agent_auth.py")
    agents_api = _text(BACKEND / "app" / "api" / "agents.py")
    policy = _text(BACKEND / "app" / "services" / "policy_service.py")
    config = _text(BACKEND / "app" / "config.py")
    main = _text(BACKEND / "app" / "main.py")
    redaction = _text(BACKEND / "app" / "services" / "redaction.py")
    ingestion = _text(BACKEND / "app" / "services" / "ingestion.py")
    action_schema = _text(BACKEND / "app" / "schemas" / "action.py")
    response_actions = _text(ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx")
    agents_ui = _text(ROOT / "frontend" / "src" / "app" / "agents" / "page.tsx")
    rotation_helper = _text(ROOT / "scripts" / "rotate_response_agent_key.py")
    checkpoint_helper = _text(ROOT / "scripts" / "manage_audit_checkpoint.py")

    # Endpoint trust must be fresh, exact-action scoped, and cleared by analyst
    # disable before a later re-enable can regain response authority.
    for fragment in (
        "AGENT_CAPABILITY_STALE_REASON",
        "_CAPABILITY_REPORT_MAX_AGE = timedelta(minutes=15)",
        "INTEGRITY_TRUST_REASON",
        "incident_integrity_compromised",
    ):
        assert fragment in policy
    for fragment in (
        "_revoke_agent_trust_state",
        "agent.supported_actions = []",
        "agent.enabled_actions = []",
        "agent.capabilities_updated_at = None",
        "agent.pending_hmac_key_b64 = None",
        "pending_key_rotation_exists",
    ):
        assert fragment in agents_api

    # Rotation keeps only a pending secret until activation and no retired secret.
    for field in (
        "pending_key_id",
        "pending_hmac_key_b64",
        "pending_key_expires_at",
        "previous_key_id",
        "previous_key_revoked_at",
    ):
        assert field in model
        assert field in migration
    for retired in ("previous_hmac_key_b64", "previous_key_expires_at"):
        assert retired not in model
        assert retired not in migration
        assert retired not in agent_auth
    assert "Retired key material is not stored" in agent_auth
    assert "verify_pending_agent_request" in agent_auth
    assert "--recover-next" in rotation_helper
    assert 'path.name + ".next"' in rotation_helper
    assert "os.replace(next_path, path)" in rotation_helper
    assert "previous_key_revoked_at" in rotation_helper

    # Obvious credential material is scrubbed before event/action/note persistence.
    for fragment in (
        'REDACTED = "[REDACTED]"',
        '"authorization"',
        '"access_token"',
        '"refresh_token"',
        '"private_key"',
        "_MAX_REDACTION_DEPTH = 20",
    ):
        assert fragment in redaction
    assert "redact_sensitive(dumped)" in ingestion
    assert "payload=redacted_payload" in ingestion
    assert "redact_credential_fields" in action_schema
    assert "redact_error_credentials" in action_schema
    assert "redact_reason_credentials" in action_schema

    # A separately retained audit prefix can be made a startup requirement.
    assert "trusted_audit_checkpoint_path" in config
    assert "QWR_TRUSTED_AUDIT_CHECKPOINT_PATH must be absolute" in config
    for fragment in (
        "_load_trusted_audit_checkpoint",
        "must not be a symbolic link",
        "must not be group/world writable",
        "verify_audit_checkpoint",
        "trusted audit checkpoint verification failed at startup",
    ):
        assert fragment in main
    for fragment in (
        "getpass.getpass",
        "QWR_ANALYST_TOKEN",
        "_atomic_private_json",
        "plain HTTP is allowed only for loopback Response",
        "The analyst bearer token was not printed",
    ):
        assert fragment in checkpoint_helper

    # UI must mirror policy rather than advertising stale or un-attested action state.
    assert "agentCapabilityFresh" in response_actions
    assert "CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000" in response_actions
    assert "eligibleAgentsFor" in response_actions
    assert "agent.enabled_actions.includes(actionType)" in response_actions
    assert 'type CapabilityStatus = "Fresh" | "Stale" | "Never reported"' in agents_ui


def test_latest_v12_surface_still_has_no_generic_remote_command_primitive() -> None:
    action_registry = _text(BACKEND / "app" / "services" / "action_registry.py")
    agent = _text(ROOT / "scripts" / "response_agent.py")
    for forbidden_action in ("run_shell", "run_command", "execute_script", "run_powershell"):
        assert forbidden_action not in action_registry
    for forbidden_primitive in (
        "import subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "shell=True",
    ):
        assert forbidden_primitive not in agent
