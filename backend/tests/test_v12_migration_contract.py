from __future__ import annotations

from pathlib import Path

from app.database.models import AgentRecord


ROOT = Path(__file__).resolve().parents[2]


def test_v12_agent_migration_extends_phase2_and_matches_current_model() -> None:
    migration = (
        ROOT / "backend" / "alembic" / "versions" / "0003_agent_capabilities.py"
    ).read_text(encoding="utf-8")

    assert 'revision = "0003_agent_caps"' in migration
    assert 'down_revision = "0002_phase2"' in migration

    expected = {
        "supported_actions",
        "enabled_actions",
        "capabilities_updated_at",
        "pending_key_id",
        "pending_hmac_key_b64",
        "pending_key_expires_at",
        "previous_key_id",
        "previous_key_revoked_at",
    }
    for field in expected:
        assert field in migration
        assert hasattr(AgentRecord, field)

    for retired_secret_field in ("previous_hmac_key_b64", "previous_key_expires_at"):
        assert retired_secret_field not in migration
        assert not hasattr(AgentRecord, retired_secret_field)


def test_v12_migration_downgrade_removes_every_added_agent_field() -> None:
    migration = (
        ROOT / "backend" / "alembic" / "versions" / "0003_agent_capabilities.py"
    ).read_text(encoding="utf-8")
    for field in (
        "previous_key_revoked_at",
        "previous_key_id",
        "pending_key_expires_at",
        "pending_hmac_key_b64",
        "pending_key_id",
        "capabilities_updated_at",
        "enabled_actions",
        "supported_actions",
    ):
        assert f'op.drop_column("agents", "{field}")' in migration
