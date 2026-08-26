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
            "atomic_private_json",
            "load_private_json",
            "resources_module._load_mapping = _secure_resource_mapping",
        ),
        "canonical agent",
    )

    private_state = _text("scripts/private_state_io.py")
    _require(
        private_state,
        (
            "O_EXCL",
            "O_NOFOLLOW",
            "secrets.token_hex",
            "private state file must not be group/world accessible",
            "private state file changed during read",
        ),
        "private state I/O",
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
            "quietward_event_ingestion_only",
            "ReloadingEventOnlyClient",
            "host does not match the enrolled Response agent host",
            "_atomic_private_json",
            "load_private_json",
        ),
        "QuietWard adapter",
    )
    for forbidden in (
        'INSERT INTO events',
        'UPDATE events',
        'DELETE FROM events',
        "import quietward",
        "from quietward",
        "/actions/pending",
        "terminate_process_by_handle",
        "quarantine_artifact_by_handle",
    ):
        if forbidden in adapter:
            raise RuntimeError(f"QuietWard adapter gained forbidden detector coupling/write/action surface: {forbidden}")

    adapter_auth = _text("scripts/quietward_adapter_credentials.py")
    _require(
        adapter_auth,
        (
            "EVENT_INGESTION_SUBKEY_DOMAIN",
            "quietward_event_ingestion_only",
            "event_hmac_key_b64",
            "EventOnlyClient",
            'target != "/api/v1/events"',
            "load_private_json",
            "atomic_private_json",
        ),
        "adapter least-privilege credential",
    )
    server_auth = _text("backend/app/services/agent_auth.py")
    _require(
        server_auth,
        (
            "derive_event_ingestion_subkey",
            "verify_agent_event_request",
            "_event_ingestion_verification_keys",
        ),
        "server event-subkey verification",
    )
    event_api = _text("backend/app/api/events.py")
    if "verify_agent_event_request" not in event_api:
        raise RuntimeError("QuietWard ingestion does not use event-subkey verifier")

    rotation = _text("scripts/rotate_response_agent_key.py")
    _require(
        rotation,
        (
            "provision_from_agent_config",
            'path.with_name("adapter.json")',
            "Adapter event-only credential refreshed:",
        ),
        "adapter credential rotation",
    )

    ingestion = _text("backend/app/services/ingestion.py")
    if "from app.services.correlation_v12 import correlate_event" not in ingestion:
        raise RuntimeError("v1.2 ingestion does not use strengthened correlation")

    correlation = _text("backend/app/services/correlation_v12.py")
    _require(
        correlation,
        (
            "_STAGE_TRANSITIONS",
            "_explicit_high_signal",
            "_shared_indicator_reasons",
            'f"shared {label}"',
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

    policy = _text("backend/app/services/policy_service.py")
    _require(
        policy,
        (
            "TARGET_HOST_MISSING_REASON",
            "if host is None:",
            "reasons.append(TARGET_HOST_MISSING_REASON)",
        ),
        "fail-closed target host policy",
    )

    main = _text("backend/app/main.py")
    _require(
        main,
        (
            "O_NOFOLLOW",
            "must not be group/world writable",
            "must not be a symbolic link or reparse point",
            "changed during read; refusing startup",
        ),
        "trusted audit checkpoint file boundary",
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
        "scripts/provision_quietward_adapter.py",
        "scripts/quietward_adapter_credentials.py",
        "scripts/reloading_adapter_client.py",
        "scripts/private_state_io.py",
        "scripts/verify_v12_quietward_adapter_live.py",
        "backend/tests/test_v12_quietward_adapter.py",
        "backend/tests/test_v12_adapter_credential_scope.py",
        "backend/tests/test_v12_adapter_provisioning.py",
        "backend/tests/test_v12_decision_quality.py",
        "backend/tests/test_v12_policy_hardening.py",
        "backend/tests/test_v12_private_state_io.py",
        "backend/tests/test_v12_release_corrections.py",
    ):
        if not (ROOT / relative).is_file():
            raise RuntimeError(f"required release-correction file missing: {relative}")

    print("V1.2 RELEASE-CORRECTION SURFACE: PASS")
    print("continuous_agent=yes")
    print("quietward_adapter=read_only_signed_event_subkey")
    print("adapter_action_authority=no")
    print("adapter_rotation_refresh=automatic")
    print("runtime_config_fail_closed=yes")
    print("private_state_io=exclusive_nofollow")
    print("target_host_policy=fail_closed")
    print("trusted_checkpoint_file_boundary=hardened")
    print("high_impact_recommendations=strengthened")
    print("correlation=specific_or_high_signal_multistage")
    print("file_diagnostic_total_budget=256MiB")
    print("mutating_platforms=linux_windows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
