from __future__ import annotations

import platform
from pathlib import Path
from typing import Any, Callable

from evidence_store import EvidenceStore, EvidenceStoreError
from response_agent_diagnostics import (
    DiagnosticError,
    collect_host_diagnostic,
    collect_network_diagnostic,
    collect_process_diagnostic,
)


def _collect_component(
    name: str,
    collector: Callable[[], dict[str, Any]],
    *,
    components: dict[str, dict[str, Any]],
    failures: dict[str, str],
) -> None:
    try:
        result = collector()
    except DiagnosticError as exc:
        failures[name] = str(exc)[:512]
        return
    if result.get("read_only") is not True or result.get("system_state_changed") is not False:
        failures[name] = "diagnostic did not satisfy read-only result contract"
        return
    components[name] = result


def _attach_process_evidence_handles(
    process_result: dict[str, Any],
    *,
    state_dir: Path,
    evidence_key: bytes,
    failures: dict[str, str],
) -> None:
    rows = process_result.get("processes")
    if not isinstance(rows, list):
        failures["process_evidence"] = "process diagnostic returned an invalid process list"
        return
    try:
        store = EvidenceStore(state_dir, evidence_key)
    except EvidenceStoreError as exc:
        failures["process_evidence"] = str(exc)[:512]
        return
    bound = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            handle = store.record_process(row)
        except EvidenceStoreError as exc:
            failures["process_evidence"] = str(exc)[:512]
            return
        if handle is not None:
            row["evidence_handle"] = handle
            bound += 1
    process_result["evidence_handle_scheme"] = "endpoint_local_hmac_v1"
    process_result["evidence_handles_bound"] = bound
    process_result["raw_process_target_parameters_required"] = False


def collect_incident_triage_bundle(
    state_dir: Path,
    network_privacy_key: bytes,
) -> dict[str, Any]:
    """Collect a bounded, read-only incident triage snapshot.

    The bundle intentionally composes only existing diagnostic collectors. It does
    not accept a target, path, PID, address, command, or shell fragment. Platform
    gaps are reported explicitly rather than replaced with unsafe fallbacks.

    Process rows receive opaque evidence handles. The handle-to-process mapping is
    retained only in the Response agent's private state directory so later approved
    containment can re-resolve and revalidate the exact observed process instance.
    """
    system = platform.system().lower()
    components: dict[str, dict[str, Any]] = {}
    failures: dict[str, str] = {}
    skipped: dict[str, str] = {}

    _collect_component(
        "host",
        lambda: collect_host_diagnostic(state_dir),
        components=components,
        failures=failures,
    )

    if system in {"linux", "windows"}:
        _collect_component(
            "process",
            collect_process_diagnostic,
            components=components,
            failures=failures,
        )
        process_result = components.get("process")
        if isinstance(process_result, dict):
            _attach_process_evidence_handles(
                process_result,
                state_dir=state_dir,
                evidence_key=network_privacy_key,
                failures=failures,
            )
    else:
        skipped["process"] = "process diagnostics are currently supported only on Windows and Linux"

    if system == "linux":
        _collect_component(
            "network",
            lambda: collect_network_diagnostic(network_privacy_key),
            components=components,
            failures=failures,
        )
    else:
        skipped["network"] = "privacy-preserving network diagnostics are currently supported only on Linux"

    return {
        "read_only": True,
        "system_state_changed": False,
        "bundle_version": "2",
        "platform": platform.system()[:64],
        "components": components,
        "component_failures": failures,
        "skipped_components": skipped,
        "component_count": len(components),
        "complete": not failures,
        "evidence_handles_local_only": True,
        "arbitrary_command_execution": False,
        "raw_process_command_lines": False,
        "raw_executable_paths": False,
        "raw_remote_network_addresses": False,
    }
