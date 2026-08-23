#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _require(text: str, fragments: tuple[str, ...], label: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in text]
    if missing:
        raise RuntimeError(f"{label} contract missing: {missing}")


def main() -> int:
    poller = _text("scripts/poll_response_agent.py")
    _require(
        poller,
        (
            "while not stop.is_set()",
            '"--once"',
            "sync_capabilities(agent)",
            "agent.poll_once()",
            "max_backoff_seconds",
        ),
        "continuous agent",
    )

    canonical = _text("scripts/response_agent_v12.py")
    _require(
        canonical,
        (
            "config must not be a symbolic link",
            "config must not be group/world accessible",
            "safe_process_termination_supported",
            "collect_file_diagnostic_v12",
        ),
        "canonical agent",
    )

    file_diag = _text("scripts/response_agent_file_v12.py")
    _require(
        file_diag,
        (
            "FILE_DIAGNOSTIC_BYTE_BUDGET = 256 * 1024 * 1024",
            '"scan_byte_budget"',
            '"scanned_bytes"',
            '"skipped_due_to_byte_budget"',
        ),
        "file diagnostic budget",
    )

    adapter = _text("scripts/forward_quietward_events.py")
    _require(
        adapter,
        (
            '"?mode=ro"',
            'connection.execute("PRAGMA query_only=ON")',
            '"source": "quietward"',
            "uuid5(",
            "quietward_database_read_only",
            "host does not match the enrolled Response agent host",
        ),
        "QuietWard adapter",
    )
    for forbidden in (
        'INSERT INTO events',
        'UPDATE events',
        'DELETE FROM events',
        "import quietward",
        "from quietward",
    ):
        if forbidden in adapter:
            raise RuntimeError(f"QuietWard adapter gained forbidden detector coupling/write: {forbidden}")

    ingestion = _text("backend/app/services/ingestion.py")
    if "from app.services.correlation_v12 import correlate_event" not in ingestion:
        raise RuntimeError("v1.2 ingestion does not use strengthened correlation")

    correlation = _text("backend/app/services/correlation_v12.py")
    _require(
        correlation,
        (
            "_STAGE_TRANSITIONS",
            "_explicit_high_signal",
            "shared process",
            "compatible high-signal attack stages:",
        ),
        "v1.2 correlation",
    )
    if "shared category" in correlation:
        raise RuntimeError("same-category-only correlation returned to v1.2")

    recommendations = _text("backend/app/services/recommendation_v12.py")
    _require(
        recommendations,
        (
            "_process_termination_justified",
            "_file_quarantine_justified",
            'event_type == "process_start"',
            'event_type in {"malware_signature", "yara_match"}',
        ),
        "high-impact recommendation gate",
    )

    registry = _text("backend/app/services/action_registry.py")
    _require(
        registry,
        (
            'supported_os=("linux", "windows"),',
            "endpoint-local keyed remote-address pseudonyms",
        ),
        "platform/action registry",
    )

    health = _text("backend/app/api/health.py")
    _require(
        health,
        (
            '"response_scope": "typed_controlled_response_v12"',
            '"generic_command_execution": False',
        ),
        "health status",
    )

    for relative in (
        "deploy/quietward-response-agent.service",
        "deploy/quietward-response-quietward-adapter.service",
        "scripts/install_response_agent_user_service.sh",
        "scripts/install_response_agent_windows.ps1",
        "scripts/install_quietward_adapter_user_service.sh",
        "scripts/install_quietward_adapter_windows.ps1",
        "scripts/verify_v12_quietward_adapter_live.py",
        "backend/tests/test_v12_quietward_adapter.py",
        "backend/tests/test_v12_decision_quality.py",
        "backend/tests/test_v12_release_corrections.py",
    ):
        if not (ROOT / relative).is_file():
            raise RuntimeError(f"required release-correction file missing: {relative}")

    print("V1.2 RELEASE-CORRECTION SURFACE: PASS")
    print("continuous_agent=yes")
    print("quietward_adapter=read_only_signed")
    print("runtime_config_fail_closed=yes")
    print("high_impact_recommendations=strengthened")
    print("correlation=specific_or_high_signal_multistage")
    print("file_diagnostic_total_budget=256MiB")
    print("mutating_platforms=linux_windows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
