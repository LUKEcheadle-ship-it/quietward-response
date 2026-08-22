from __future__ import annotations

from pathlib import Path

from app.v13_public_credential_model import AgentPublicCredentialRecord


ROOT = Path(__file__).resolve().parents[2]


def test_v13_public_credential_model_contains_only_public_verification_material() -> None:
    columns = set(AgentPublicCredentialRecord.__table__.columns.keys())
    assert columns == {
        "credential_id",
        "agent_id",
        "key_id",
        "algorithm",
        "protocol_version",
        "public_key_b64",
        "status",
        "created_at",
        "activated_at",
        "revoked_at",
        "expires_at",
    }
    for forbidden in (
        "private_key",
        "private_key_b64",
        "secret",
        "hmac_key_b64",
        "encrypted_private_key",
    ):
        assert forbidden not in columns


def test_v13_public_credential_migration_contains_no_private_or_symmetric_key_material() -> None:
    migration = (
        ROOT
        / "backend"
        / "alembic"
        / "versions"
        / "0004_agent_public_credentials.py"
    ).read_text(encoding="utf-8")
    assert 'revision = "0004_agent_public_credentials"' in migration
    assert 'down_revision = "0003_agent_caps"' in migration
    assert '"public_key_b64"' in migration
    assert '"algorithm"' in migration
    assert '"protocol_version"' in migration
    assert '"revoked_at"' in migration
    for forbidden in (
        "private_key",
        "private_key_b64",
        "hmac_key_b64",
        "pending_hmac_key_b64",
        "encrypted_private_key",
    ):
        assert forbidden not in migration.lower()


def test_v13_public_credential_storage_is_isolated_from_v12_agent_table() -> None:
    migration = (
        ROOT
        / "backend"
        / "alembic"
        / "versions"
        / "0004_agent_public_credentials.py"
    ).read_text(encoding="utf-8")
    assert 'op.create_table(\n        "agent_public_credentials"' in migration
    assert 'op.add_column("agents"' not in migration
    assert "does not switch the live v1.2 hmac authentication path" in migration.lower()
