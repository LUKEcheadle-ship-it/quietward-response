from __future__ import annotations

import ctypes
import os
import platform
import select
import signal
from ctypes import wintypes
from pathlib import Path, PureWindowsPath
from typing import Any

from evidence_store import EvidenceStore, EvidenceStoreError
from response_agent_diagnostics import DiagnosticError, collect_process_diagnostic


class ProcessContainmentError(RuntimeError):
    pass


_PROTECTED_IMAGES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "systemd", "init", "kthreadd",
}
_EXIT_CONFIRM_TIMEOUT_SECONDS = 3.0


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


def _linux_identity_matches(process: dict[str, Any]) -> bool:
    """Read identity after obtaining the stable process descriptor; fail closed."""
    try:
        text = (Path("/proc") / str(process["pid"]) / "stat").read_text(
            encoding="utf-8", errors="strict"
        )
        begin, end = text.find("("), text.rfind(")")
        if begin < 0 or end <= begin:
            return False
        fields = text[end + 2:].split()
        return (
            len(fields) > 19
            and fields[0] not in {"Z", "X", "x"}
            and int(text[:begin].strip()) == process["pid"]
            and int(fields[1]) == process["parent_pid"]
            and text[begin + 1:end].casefold() == str(process["image"]).casefold()
            and fields[19] == str(process["start_marker"])
        )
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return False


def _pidfd_exited(pidfd: int, timeout_ms: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    for descriptor, events in poller.poll(timeout_ms):
        if descriptor != pidfd or events & (select.POLLERR | select.POLLNVAL):
            raise ProcessContainmentError("Linux could not confirm process-descriptor state")
        if events & (select.POLLIN | select.POLLHUP):
            return True
        raise ProcessContainmentError("Linux returned an unknown process-descriptor state")
    return False


def _terminate_linux(process: dict[str, Any]) -> bool:
    # Never fall back to kill(pid): PID reuse can occur between validation and kill.
    # A pidfd pins the process object, including if its numeric PID is later reused.
    if not callable(getattr(os, "pidfd_open", None)) or not callable(
        getattr(signal, "pidfd_send_signal", None)
    ):
        raise ProcessContainmentError("Linux process containment requires pidfd support")
    pidfd: int | None = None
    try:
        pidfd = os.pidfd_open(int(process["pid"]), 0)
        if not _linux_identity_matches(process):
            raise ProcessContainmentError("evidence-bound process identity changed or is unavailable")
        if _pidfd_exited(pidfd, 0):
            raise ProcessContainmentError("evidence-bound process has already exited")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
        if not _pidfd_exited(pidfd, int(_EXIT_CONFIRM_TIMEOUT_SECONDS * 1000)):
            raise ProcessContainmentError(
                "termination was requested but process-descriptor exit was not confirmed"
            )
        return True
    except OSError as exc:
        # A read/permission/descriptor error is not proof of process exit.
        raise ProcessContainmentError("Linux evidence-bound containment failed") from exc
    finally:
        if pidfd is not None:
            os.close(pidfd)


def _windows_api() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.IsProcessCritical.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.IsProcessCritical.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _terminate_windows(process: dict[str, Any]) -> bool:
    if os.name != "nt":
        raise ProcessContainmentError("Windows process termination requested on a non-Windows host")
    try:
        kernel32 = _windows_api()
    except (AttributeError, OSError) as exc:
        raise ProcessContainmentError("Windows identity/critical-process APIs are unavailable") from exc
    # Query, terminate and wait all use THIS handle, never a second OpenProcess(pid).
    handle = kernel32.OpenProcess(0x0001 | 0x1000 | 0x00100000, False, int(process["pid"]))
    if not handle:
        raise ProcessContainmentError("evidence-bound process could not be opened for containment")
    try:
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not kernel32.GetProcessTimes(
            handle, ctypes.byref(created), ctypes.byref(exited),
            ctypes.byref(kernel), ctypes.byref(user),
        ):
            raise ProcessContainmentError("Windows process creation identity is unavailable")
        marker = str((int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime))
        if marker != str(process["start_marker"]):
            raise ProcessContainmentError("evidence-bound process instance changed")
        size = wintypes.DWORD(32768)
        image = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, image, ctypes.byref(size)):
            raise ProcessContainmentError("Windows process image identity is unavailable")
        if PureWindowsPath(image.value).name.casefold() != str(process["image"]).casefold():
            raise ProcessContainmentError("evidence-bound process image identity changed")
        critical = wintypes.BOOL()
        if not kernel32.IsProcessCritical(handle, ctypes.byref(critical)):
            raise ProcessContainmentError("Windows critical-process status is unavailable")
        if critical.value:
            raise ProcessContainmentError("Windows critical process is protected")
        if kernel32.WaitForSingleObject(handle, 0) != 0x00000102:
            raise ProcessContainmentError("Windows process is not confirmed active")
        if not kernel32.TerminateProcess(handle, 1):
            raise ProcessContainmentError("Windows refused evidence-bound process termination")
        if kernel32.WaitForSingleObject(handle, int(_EXIT_CONFIRM_TIMEOUT_SECONDS * 1000)) != 0:
            raise ProcessContainmentError("termination requested but Windows process exit was not confirmed")
        return True
    finally:
        kernel32.CloseHandle(handle)


def _request_termination(process: dict[str, Any]) -> tuple[str, bool]:
    if platform.system().lower() == "linux":
        return "SIGTERM", _terminate_linux(process)
    if os.name == "nt":
        return "TerminateProcess", _terminate_windows(process)
    raise ProcessContainmentError("evidence-bound process containment is supported only on Windows and Linux")


def terminate_evidence_process(
    state_dir: Path,
    evidence_key: bytes,
    evidence_handle: str,
) -> dict[str, Any]:
    """Terminate only the signed, revalidated process instance behind a local handle."""
    try:
        diagnostic = collect_process_diagnostic()
    except DiagnosticError as exc:
        raise ProcessContainmentError(str(exc)) from exc
    if not isinstance(diagnostic, dict) or not isinstance(diagnostic.get("processes"), list):
        raise ProcessContainmentError("process diagnostic returned an invalid process list")
    try:
        process = EvidenceStore(state_dir, evidence_key).resolve_process(
            evidence_handle, [row for row in diagnostic["processes"] if isinstance(row, dict)]
        )
    except EvidenceStoreError as exc:
        raise ProcessContainmentError(str(exc)) from exc
    protected = _protected_reason(process)
    if protected:
        raise ProcessContainmentError(protected)
    mechanism, confirmed = _request_termination(process)
    if confirmed is not True:
        raise ProcessContainmentError("termination was requested but process exit was not confirmed")
    return {
        "read_only": False,
        "system_state_changed": True,
        "containment_type": "terminate_evidence_process",
        "evidence_handle": evidence_handle,
        "process": {
            "pid": int(process["pid"]),
            "image": str(process["image"])[:128],
            "parent_pid": int(process["parent_pid"]),
        },
        "termination_mechanism": mechanism,
        "termination_requested": True,
        "confirmed_original_process_exited": True,
        "execution_time_identity_revalidated": True,
        "stable_process_reference_used": True,
        "arbitrary_pid_accepted": False,
        "arbitrary_command_execution": False,
    }
