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

    combined_checkpoint_docs = "\n".join((acceptance, threat_model, release_notes)).lower()
    assert "audit checkpoint" in combined_checkpoint_docs
    assert "full-chain" in combined_checkpoint_docs or "full chain" in combined_checkpoint_docs
    assert "suffix" in combined_checkpoint_docs
    assert "qwr_audit_checkpoint_secret" in combined_checkpoint_docs
    assert "free-form pid, path, command, or opaque-handle input" in acceptance.lower()

    combined_agent_docs = "\n".join((acceptance, threat_model, release_notes)).lower()
    assert "signed agent capability" in combined_agent_docs or "signed endpoint capability" in combined_agent_docs
    assert "arbitrary_command_execution=false" in combined_agent_docs
    assert "two-phase" in combined_agent_docs
    assert "pending credential" in combined_agent_docs
    assert "previous" in combined_agent_docs and "recovery" in combined_agent_docs
    assert "--recover-next" in combined_agent_docs
    assert "cannot prepare another rotation" in combined_agent_docs
    assert "poll_response_agent.py" in release_notes


def test_v12_agent_hardening_files_are_release_tracked() -> None:
    required = (
        "backend/alembic/versions/0003_agent_capabilities.py",
        "backend/tests/test_v12_agent_capabilities.py",
        "backend/tests/test_v12_agent_key_rotation.py",
        "scripts/poll_response_agent.py",
        "scripts/response_agent_capabilities.py",
        "scripts/rotate_response_agent_key.py",
        "scripts/verify_v12_alpha_live_capabilities.py",
    )
    for relative in required:
        assert (ROOT / relative).is_file(), relative


def test_v12_docs_keep_detector_repository_separation_explicit() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    acceptance = (ROOT / "docs" / "V12_ALPHA_ACCEPTANCE.md").read_text(
        encoding="utf-8"
    ).lower()
    assert "separate product and repository from quietward" in readme
    assert "does not require or modify any detector repository" in acceptance
