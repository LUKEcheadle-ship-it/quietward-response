from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_production_runtime_has_no_old_key_grace_or_retired_hmac_storage_references() -> None:
    roots = [ROOT / "backend" / "app", ROOT / "backend" / "alembic" / "versions"]
    forbidden = (
        "allow_previous_key",
        "previous_hmac_key_b64",
        "previous_key_expires_at",
    )
    findings: list[str] = []
    for base in roots:
        for path in base.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for fragment in forbidden:
                if fragment in text:
                    findings.append(f"{path.relative_to(ROOT)}: {fragment}")
    assert findings == []


def test_production_rotation_keeps_only_non_secret_revocation_metadata() -> None:
    model = (ROOT / "backend" / "app" / "database" / "models.py").read_text(
        encoding="utf-8"
    )
    auth = (ROOT / "backend" / "app" / "services" / "agent_auth.py").read_text(
        encoding="utf-8"
    )
    assert "previous_key_id" in model
    assert "previous_key_revoked_at" in model
    assert "agent.previous_key_id = old_key_id" in auth
    assert "agent.previous_key_revoked_at = now" in auth
