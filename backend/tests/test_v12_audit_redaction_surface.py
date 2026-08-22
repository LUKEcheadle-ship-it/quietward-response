from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_record_audit_centrally_redacts_before_hashing() -> None:
    source = (
        ROOT / "backend" / "app" / "services" / "audit_service.py"
    ).read_text(encoding="utf-8")
    start = source.index("def record_audit(")
    end = source.index("\ndef verify_audit_chain", start)
    record_source = source[start:end]

    assert "candidate = redact_sensitive(details or {})" in record_source
    assert "resolved_details" in record_source
    assert "details=resolved_details" in record_source
    assert "Central loss prevention" in record_source

    redaction_position = record_source.index("candidate = redact_sensitive(details or {})")
    hash_position = record_source.index("entry_hash = _hash_entry(")
    record_position = record_source.index("record = AuditRecord(")
    assert redaction_position < hash_position < record_position


def test_audit_service_does_not_log_detail_values() -> None:
    source = (
        ROOT / "backend" / "app" / "services" / "audit_service.py"
    ).read_text(encoding="utf-8")
    assert '"details": resolved_details' not in source[source.index("logger.info(") :]
    assert "logger.info" in source
    assert '"entry_hash": entry_hash' in source
