from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_v11_alpha_historical_metadata_remains_available() -> None:
    """v1.1 is historical qualification evidence, not the current branch version."""
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    acceptance = (ROOT / "docs" / "V11_ALPHA_ACCEPTANCE.md").read_text(
        encoding="utf-8"
    )
    release_notes = (
        ROOT / "docs" / "releases" / "v1.1.0-alpha.1.md"
    ).read_text(encoding="utf-8")

    assert "## 1.1.0-alpha.1" in changelog
    assert "v1.1.0-alpha.1" in acceptance
    assert "1.1.0a1" in acceptance
    assert "feature/response-diagnostic-expansion" in acceptance
    assert "v1.1.0-alpha.1" in release_notes
    assert "standalone" in acceptance.lower()
    assert "standalone" in release_notes.lower()
    assert "does not require changes to any detector repository" in release_notes
