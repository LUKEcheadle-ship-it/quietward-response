from __future__ import annotations

from pathlib import Path

from app.schemas.agent import AgentRead


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def test_normal_agent_schema_exposes_identifiers_not_verification_key_material() -> None:
    fields = set(AgentRead.model_fields)
    assert "key_id" in fields
    assert "supported_actions" in fields
    assert "enabled_actions" in fields
    assert "capabilities_updated_at" in fields

    forbidden = {
        "hmac_key_b64",
        "pending_hmac_key_b64",
        "pending_key_id",
        "pending_key_expires_at",
        "secret",
    }
    assert fields.isdisjoint(forbidden)


def test_normal_agent_api_serializer_never_returns_server_verification_material() -> None:
    source = (BACKEND / "app" / "api" / "agents.py").read_text(encoding="utf-8")
    start = source.index("def _agent_to_dict")
    end = source.index("\n\n@router.post", start)
    serializer = source[start:end]
    for forbidden in (
        '"hmac_key_b64"',
        '"pending_hmac_key_b64"',
        '"pending_key_id"',
        '"pending_key_expires_at"',
        '"secret"',
    ):
        assert forbidden not in serializer


def test_one_time_secret_endpoints_are_no_store_and_audit_omits_secret_material() -> None:
    source = (BACKEND / "app" / "api" / "agents.py").read_text(encoding="utf-8")
    # Enrollment and prepare-rotation legitimately return a secret exactly once.
    # Both must keep no-store/pragma cache controls adjacent in this API module.
    assert source.count('response.headers["Cache-Control"] = "no-store, max-age=0"') >= 3
    assert source.count('response.headers["Pragma"] = "no-cache"') >= 3

    # Audit metadata may contain key identifiers and deadlines, never usable HMAC
    # material or the one-time plaintext secret.
    for forbidden in (
        '"hmac_key_b64":',
        '"pending_hmac_key_b64":',
        '"secret": secret',
    ):
        # The final form is allowed only in the explicit one-time HTTP return body,
        # so inspect audit details blocks separately rather than banning it globally.
        if forbidden == '"secret": secret':
            continue
        assert forbidden not in source

    prepared_audit = source[source.index('action="agent_key_rotation_prepared"'):]
    prepared_audit = prepared_audit[: prepared_audit.index("db.commit()")]
    assert "hmac_key_b64" not in prepared_audit
    assert '"secret"' not in prepared_audit

    rotated_audit = source[source.index('action="agent_key_rotated"'):]
    rotated_audit = rotated_audit[: rotated_audit.index("db.commit()")]
    assert "hmac_key_b64" not in rotated_audit
    assert '"secret"' not in rotated_audit


def test_agent_verification_material_is_not_logged_by_auth_service() -> None:
    source = (BACKEND / "app" / "services" / "agent_auth.py").read_text(encoding="utf-8")
    assert "logger." not in source
    assert "print(" not in source
