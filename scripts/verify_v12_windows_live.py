#!/usr/bin/env python3
from __future__ import annotations

import platform

import verify_v12_alpha_live as base
import verify_v12_alpha_live_capabilities as capability_gate

_original_event = base._event


def _windows_event(host_id: str, event_type: str, category: str, severity: str):
    value = _original_event(host_id, event_type, category, severity)
    metadata = dict(value.get("metadata") or {})
    metadata["operating_system"] = "Windows"
    value["metadata"] = metadata
    return value


def main() -> int:
    if platform.system().lower() != "windows":
        raise RuntimeError("v1.2 Windows live qualification requires a native Windows host")
    base._event = _windows_event
    result = capability_gate.main()
    if result != 0:
        return result
    print("V1.2 WINDOWS LIVE ACCEPTANCE: PASS")
    print("server_host_os=Windows")
    print("canonical_agent=ResponseAgent_v1.2")
    print("disposable_process_containment=qualified")
    print("managed_file_quarantine_restore=qualified")
    print("raw_pid_path_targeting=rejected")
    print("generic_command_surface=absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
