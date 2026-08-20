from __future__ import annotations

from pathlib import Path

from app import __version__


ROOT = Path(__file__).resolve().parents[2]


def test_v11_alpha_metadata_is_consistent() -> None:
    assert __version__ == "1.1.0a1"
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    acceptance = (ROOT / "docs" / "V11_ALPHA_ACCEPTANCE.md").read_text(
        encoding="utf-8"
    )
    assert "## 1.1.0-alpha.1" in changelog
    assert "v1.1.0-alpha.1" in acceptance
    assert "1.1.0a1" in acceptance
    assert "feature/response-diagnostic-expansion" in acceptance
