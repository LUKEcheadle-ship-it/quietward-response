from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_rotation_helper_matches_immediate_revocation_response_contract() -> None:
    text = (ROOT / "scripts" / "rotate_response_agent_key.py").read_text(encoding="utf-8")
    assert 'value.get("previous_key_revoked_at")' in text
    assert "Previous key revoked at:" in text
    assert "previous_key_expires_at" not in text
    assert "sync_capabilities(rotated_agent)" in text
    assert "os.replace(next_path, path)" in text
    assert "The new agent secret was not printed." in text
