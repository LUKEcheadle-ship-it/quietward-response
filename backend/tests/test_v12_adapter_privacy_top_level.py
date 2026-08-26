from __future__ import annotations

from scripts.quietward_adapter_privacy import sanitize_quietward_event_payload


def test_adapter_drops_unreviewed_top_level_fields_before_transmission() -> None:
    payload = {
        "schema_version": "1.0",
        "event_id": "11111111-1111-4111-8111-111111111111",
        "source": "quietward",
        "host_id": "host-test",
        "timestamp": "2026-08-26T12:00:00Z",
        "event_type": "process_start",
        "severity": "high",
        "confidence": 1.0,
        "summary": "bounded",
        "evidence": {},
        "metadata": {},
        "future_raw_export": "must-never-cross",
    }
    sanitized = sanitize_quietward_event_payload(payload)
    assert "future_raw_export" not in sanitized
    assert "must-never-cross" not in str(sanitized)
