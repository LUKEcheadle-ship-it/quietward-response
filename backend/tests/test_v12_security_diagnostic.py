from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.diagnose_response_security import Check, _base_url, _parse_time


def test_security_diagnostic_transport_boundary_matches_agent_tools() -> None:
    assert _base_url("http://127.0.0.1:8002/") == "http://127.0.0.1:8002"
    assert _base_url("https://response.example.test/") == "https://response.example.test"

    import pytest
    from scripts.diagnose_response_security import DiagnoseError

    with pytest.raises(DiagnoseError, match="plain HTTP.*loopback"):
        _base_url("http://198.51.100.50:8002")
    with pytest.raises(DiagnoseError, match="embedded credentials"):
        _base_url("https://analyst:secret@response.example.test")


def test_security_diagnostic_timestamp_parser_is_timezone_safe() -> None:
    parsed = _parse_time("2026-08-21T18:00:00Z")
    assert parsed == datetime(2026, 8, 21, 18, 0, tzinfo=timezone.utc)
    assert _parse_time("not-a-time") is None
    assert _parse_time(None) is None


def test_security_diagnostic_source_is_read_only_and_does_not_print_token() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "diagnose_response_security.py").read_text(encoding="utf-8")
    assert "QWR_ANALYST_TOKEN" in source
    assert "getpass.getpass" in source
    assert "The analyst bearer token was not printed." in source
    assert "print(token" not in source
    assert "method=\"POST\"" in source  # only checkpoint verification payload
    for forbidden in (
        "/approve",
        "/reject",
        'method="PATCH"',
        'method="DELETE"',
        "subprocess",
        "os.system",
    ):
        assert forbidden not in source


def test_security_diagnostic_status_contract_is_simple_and_machine_readable() -> None:
    values = [
        Check("health", "PASS", "ok"),
        Check("agent_capabilities", "WARN", "stale=1"),
        Check("audit_chain", "FAIL", "invalid"),
    ]
    assert [item.status for item in values] == ["PASS", "WARN", "FAIL"]
