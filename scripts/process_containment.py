from __future__ import annotations

import ctypes
import os
import platform
import signal
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from evidence_store import EvidenceStore, EvidenceStoreError
from response_agent_diagnostics import DiagnosticError, collect_process_diagnostic


class ProcessContainmentError(RuntimeError):
    pass


_PROTECTED_IMAGES = {
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "svchost.exe",
    "systemd",
    "init",
    "kthreadd",
}


def _protected_reason(process: dict[str, Any]) -> str | None:
    pid = int(process["pid"])
    image = str(process["image"]).casefold()
    if pid <= 2:
        return "system-critical PID is protected"
    if pid in {os.getpid(), os.getppid()}:
        return "Response agent process lineage is protected"
    if image in _PROTECTED_IMAGES:
        return f"protected system process image: {image}"
    return None


def _terminate_windows(pid: int) -> None:
    if os.name != "nt":
        raise ProcessContainmentError("Windows process termination requested on a non-Windows host")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_TERMINATE = 0x0001
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        raise ProcessContainmentError("evidence-bound process could not be opened for termination")
    try:
        if not kernel32.TerminateProcess(handle, 1):
            raise ProcessContainmentError("Windows refused evidence-bound process termination")
    finally:
        kernel32.CloseHandle(handle)


def _request_termination(pid: int) -> str:
    system = platform.system().lower()
    if system == "linux":
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError) as exc:
            raise ProcessContainmentError(f"Linux process termination failed: {exc}") from exc
        return "SIGTERM"
    if os.name == "nt":
        _terminate_windows(pid)
        return "TerminateProcess"
    raise ProcessContainmentError("evidence-bound process containment is supported only on Windows and Linux")


def terminate_evidence_process(
    state_dir: Path,
    evidence_key: bytes,
    evidence_handle: str,
) -> dict[str, Any]:
    """Terminate only the exact process instance represented by a local evidence handle."""
    try:
        before_rows = collect_process_diagnostic().get("processes", [])
    except DiagnosticError as exc:
        raise ProcessContainmentError(str(exc)) from exc
    if not isinstance(before_rows, list):
        raise ProcessContainmentError("process diagnostic returned an invalid process list")
    try:
        process = EvidenceStore(state_dir, evidence_key).resolve_process(
            evidence_handle,
            [row for row in before_rows if isinstance(row, dict)],
        )
    except EvidenceStoreError as exc:
        raise ProcessContainmentError(str(exc)) from exc

    protected = _protected_reason(process)
    if protected:
        raise ProcessContainmentError(protected)

    pid = int(process["pid"])
    mechanism = _request_termination(pid)
    time.sleep(0.15)

    try:
        after_rows = collect_process_diagnostic().get("processes", [])
    except DiagnosticError:
        after_rows = []
    still_present = False
    if isinstance(after_rows, list):
        still_present = any(
            isinstance(row, dict) and int(row.get("pid", -1)) == pid
            for row in after_rows
        )

    return {
        "read_only": False,
        "system_state_changed": True,
        "containment_type": "terminate_evidence_process",
        "evidence_handle": evidence_handle,
        "process": {
            "pid": pid,
            "image": str(process["image"])[:128],
            "parent_pid": int(process["parent_pid"]),
        },
        "termination_mechanism": mechanism,
        "termination_requested": True,
        "confirmed_not_present_after_request": not still_present,
        "execution_time_identity_revalidated": True,
        "arbitrary_pid_accepted": False,
        "arbitrary_command_execution": False,
    }
