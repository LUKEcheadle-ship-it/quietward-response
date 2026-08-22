from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "backend" / "alembic" / "versions"


def test_v13_public_credential_migrations_form_linear_chain() -> None:
    m4 = (VERSIONS / "0004_agent_public_credentials.py").read_text(encoding="utf-8")
    m5 = (VERSIONS / "0005_agent_public_credential_indexes.py").read_text(encoding="utf-8")
    m6 = (VERSIONS / "0006_agent_public_credential_uniqueness.py").read_text(encoding="utf-8")
    assert 'revision = "0004_agent_public_credentials"' in m4
    assert 'down_revision = "0003_agent_caps"' in m4
    assert 'revision = "0005_agent_public_credential_indexes"' in m5
    assert 'down_revision = "0004_agent_public_credentials"' in m5
    assert 'revision = "0006_agent_public_credential_uniqueness"' in m6
    assert 'down_revision = "0005_agent_public_credential_indexes"' in m6


def test_v13_database_enforces_one_active_and_one_pending_per_agent() -> None:
    m6 = (VERSIONS / "0006_agent_public_credential_uniqueness.py").read_text(encoding="utf-8")
    assert '"uq_agent_public_credentials_one_active"' in m6
    assert '"uq_agent_public_credentials_one_pending"' in m6
    assert "unique=True" in m6
    assert "status = 'active'" in m6
    assert "status = 'pending'" in m6
    assert "postgresql_where" in m6
    assert "sqlite_where" in m6


def test_v13_public_credential_table_never_stores_private_or_symmetric_secret_material() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            VERSIONS / "0004_agent_public_credentials.py",
            VERSIONS / "0005_agent_public_credential_indexes.py",
            VERSIONS / "0006_agent_public_credential_uniqueness.py",
        )
    ).lower()
    for forbidden in (
        "private_key_b64",
        "hmac_key_b64",
        "pending_hmac_key_b64",
        "encrypted_private_key",
        "secret_key",
    ):
        assert forbidden not in combined
