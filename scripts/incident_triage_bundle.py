from __future__ import annotations

import platform
from pathlib import Path
from typing import Any, Callable

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


def collect_incident_triage_bundle(
    state_dir: Path,
    network_privacy_key: bytes,
) -> dict[str, Any]:
    """Collect a bounded, read-only incident triage snapshot.

    The bundle intentionally composes only existing diagnostic collectors. It does
    not accept a target, path, PID, address, command, or shell fragment. Platform
    gaps are reported explicitly rather than replaced with unsafe fallbacks.
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
        "bundle_version": "1",
        "platform": platform.system()[:64],
        "components": components,
        "component_failures": failures,
        "skipped_components": skipped,
        "component_count": len(components),
        "complete": not failures,
        "arbitrary_command_execution": False,
        "raw_process_command_lines": False,
        "raw_executable_paths": False,
        "raw_remote_network_addresses": False,
    }
