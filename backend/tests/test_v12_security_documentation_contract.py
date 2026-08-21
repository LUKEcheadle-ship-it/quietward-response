from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_v12_hardening_addendum_matches_implemented_security_boundary() -> None:
    text = (ROOT / "docs" / "V12_SECURITY_HARDENING_ADDENDUM.md").read_text(
        encoding="utf-8"
    ).lower()
    required = (
        "15 minutes",
        "fresh signed capability",
        "disabling an agent clears capability state",
        "no retired hmac key material column",
        "integrity",
        "medium/high-impact host mutation",
        "credential loss prevention",
        "redaction, not database encryption",
        "qwr_trusted_audit_checkpoint_path",
        "group/world writable",
        "manage_audit_checkpoint.py",
        "no raw pid",
        "no raw file path",
        "generic remote administration",
        "database-only compromise",
        "asymmetric endpoint signatures",
        "do not implement custom cryptography",
        "finalize_v12_alpha.py",
    )
    missing = [fragment for fragment in required if fragment not in text]
    assert missing == []


def test_v12_release_notes_do_not_claim_encryption_or_old_key_grace() -> None:
    text = (
        ROOT / "docs" / "releases" / "v1.2.0-alpha.1.md"
    ).read_text(encoding="utf-8").lower()
    assert "redaction, not database encryption" in text
    assert "no retired hmac-key-material column" in text
    assert "immediately revokes the old credential" in text
    assert "signed endpoint capability negotiation" in text
    assert "integrity trust freeze" in text
    assert "trusted audit checkpoint" in text
    assert "old-key grace" not in text
    assert "previous_key_expires_at" not in text


def test_v13_key_protection_design_keeps_crypto_migration_explicitly_unimplemented() -> None:
    text = (ROOT / "docs" / "V13_AGENT_KEY_PROTECTION_DESIGN.md").read_text(
        encoding="utf-8"
    ).lower()
    assert "not implemented in v1.2" in text
    assert "database-only compromise must not be sufficient" in text
    assert "asymmetric endpoint signatures" in text
    assert "ed25519" in text
    assert "authenticated encryption at rest" in text
    assert "vetted cryptographic library" in text
    assert "no custom cipher/mac construction" in text
    assert "no automatic fallback to plaintext" in text
