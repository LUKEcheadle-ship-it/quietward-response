from __future__ import annotations

from pathlib import Path

from app import __version__


ROOT = Path(__file__).resolve().parents[2]


def test_v12_alpha_release_metadata_is_consistent() -> None:
    assert __version__ == "1.2.0a1"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    acceptance = (ROOT / "docs" / "V12_ALPHA_ACCEPTANCE.md").read_text(
        encoding="utf-8"
    )
    threat_model = (ROOT / "docs" / "V12_ALPHA_THREAT_MODEL.md").read_text(
        encoding="utf-8"
    )
    release_notes = (
        ROOT / "docs" / "releases" / "v1.2.0-alpha.1.md"
    ).read_text(encoding="utf-8")

    for text in (readme, changelog, acceptance, release_notes):
        assert "v1.2.0-alpha.1" in text or "1.2.0-alpha.1" in text
    assert "1.2.0a1" in readme
    assert "1.2.0a1" in acceptance
    assert "feature/response-v12-hardening" in readme
    assert "feature/response-v12-hardening" in acceptance
    assert "opaque" in readme.lower()
    assert "incident-bound" in threat_model.lower()
    assert "raw pid" in readme.lower()
    assert "raw pid" in threat_model.lower()
    assert "viewer" in readme and "responder" in readme and "admin" in readme
    assert "finalize_v12_alpha.py" in readme
    assert "finalize_v12_alpha.py" in acceptance


def test_v12_docs_keep_detector_repository_separation_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    acceptance = (ROOT / "docs" / "V12_ALPHA_ACCEPTANCE.md").read_text(
        encoding="utf-8"
    ).lower()
    assert "separate product and repository from quietward" in readme
    assert "does not require or modify any detector repository" in acceptance
