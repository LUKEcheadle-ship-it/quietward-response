from __future__ import annotations

import ctypes
import hashlib
import hmac
import ipaddress
import os
import platform
import shutil
import socket
from ctypes import wintypes
from pathlib import Path
from typing import Any


MAX_PROCESS_RESULTS = 128
MAX_NETWORK_RESULTS = 256


class DiagnosticError(RuntimeError):
    pass


def collect_host_diagnostic(state_dir: Path) -> dict[str, Any]:
    """Return bounded host health metadata without launching external commands."""
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    disk = shutil.disk_usage(state_dir)
    uptime_seconds: float | None = None
    if platform.system().lower() == "linux":
        try:
            uptime_seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
        except (OSError, ValueError, IndexError):
            uptime_seconds = None
    load_average: list[float] | None = None
    if hasattr(os, "getloadavg"):
        try:
            load_average = [round(value, 3) for value in os.getloadavg()]
        except OSError:
            load_average = None
    return {
        "read_only": True,
        "system_state_changed": False,
        "platform": platform.system()[:64],
        "platform_release": platform.release()[:128],
        "machine": platform.machine()[:64],
        "cpu_count": os.cpu_count(),
        "uptime_seconds": uptime_seconds,
        "load_average": load_average,
        "agent_state_disk": {
            "total": int(disk.total),
            "used": int(disk.used),
            "free": int(disk.free),
        },
    }


def _linux_process(pid: int) -> dict[str, Any] | None:
    proc = Path("/proc") / str(pid)
    try:
        text = (proc / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    open_paren = text.find("(")
    close_paren = text.rfind(")")
    if open_paren < 0 or close_paren <= open_paren:
        return None
    fields = text[close_paren + 2 :].split()
    if len(fields) < 2:
        return None
    try:
        parent_pid = int(fields[1])
    except ValueError:
        return None
    return {
        "pid": pid,
        "parent_pid": parent_pid,
        "image": text[open_paren + 1 : close_paren][:128] or "unknown",
    }


def _windows_processes() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    TH32CS_SNAPPROCESS = 0x00000002
    invalid_handle = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if ctypes.cast(snapshot, ctypes.c_void_p).value == invalid_handle:
        raise DiagnosticError("Windows process snapshot failed")
    rows: list[dict[str, Any]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            rows.append(
                {
                    "pid": int(entry.th32ProcessID),
                    "parent_pid": int(entry.th32ParentProcessID),
                    "image": str(entry.szExeFile)[:128] or "unknown",
                }
            )
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return rows


def collect_process_diagnostic() -> dict[str, Any]:
    """Return process names/PIDs only; never command lines, environment, or paths."""
    system = platform.system().lower()
    if os.name == "nt":
        all_rows = _windows_processes()
    elif system == "linux":
        all_rows = []
        try:
            entries = list(Path("/proc").iterdir())
        except OSError as exc:
            raise DiagnosticError("Linux /proc is unavailable") from exc
        for entry in entries:
            if not entry.name.isdigit():
                continue
            row = _linux_process(int(entry.name))
            if row is not None:
                all_rows.append(row)
    else:
        raise DiagnosticError("process diagnostics are supported only on Windows and Linux")

    all_rows.sort(key=lambda item: int(item["pid"]))
    return {
        "read_only": True,
        "system_state_changed": False,
        "processes": all_rows[:MAX_PROCESS_RESULTS],
        "truncated": len(all_rows) > MAX_PROCESS_RESULTS,
        "command_lines_returned": False,
        "executable_paths_returned": False,
    }


_TCP_STATES = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_received",
    "04": "fin_wait_1",
    "05": "fin_wait_2",
    "06": "time_wait",
    "07": "closed",
    "08": "close_wait",
    "09": "last_ack",
    "0A": "listen",
    "0B": "closing",
}
_PROC_TABLES = (
    ("tcp", "ipv4", Path("/proc/net/tcp")),
    ("tcp", "ipv6", Path("/proc/net/tcp6")),
    ("udp", "ipv4", Path("/proc/net/udp")),
    ("udp", "ipv6", Path("/proc/net/udp6")),
)


def _decode_address(raw: str, family: str) -> str:
    try:
        value = bytes.fromhex(raw)
    except ValueError as exc:
        raise DiagnosticError("Linux network table contained an invalid address") from exc
    if family == "ipv4":
        if len(value) != 4:
            raise DiagnosticError("invalid IPv4 address length")
        packed = value[::-1]
        af = socket.AF_INET
    else:
        if len(value) != 16:
            raise DiagnosticError("invalid IPv6 address length")
        packed = b"".join(value[index : index + 4][::-1] for index in range(0, 16, 4))
        af = socket.AF_INET6
    try:
        return socket.inet_ntop(af, packed)
    except OSError as exc:
        raise DiagnosticError("network address could not be decoded") from exc


def _endpoint(value: str, family: str) -> tuple[str, int]:
    address_raw, separator, port_raw = value.partition(":")
    if separator != ":":
        raise DiagnosticError("network endpoint format is invalid")
    try:
        return _decode_address(address_raw, family), int(port_raw, 16)
    except ValueError as exc:
        raise DiagnosticError("network port is invalid") from exc


def _scope(address: str) -> str:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if value.is_unspecified:
        return "unspecified"
    if value.is_loopback:
        return "loopback"
    if value.is_link_local:
        return "link_local"
    if value.is_multicast:
        return "multicast"
    if value.is_private:
        return "private"
    if value.is_global:
        return "public"
    return "reserved"


def _address_pseudonym(address: str, privacy_key: bytes) -> str:
    return hmac.new(
        privacy_key,
        ("qwr-network-diagnostic-v1:" + address).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


def collect_network_diagnostic(privacy_key: bytes) -> dict[str, Any]:
    """Read Linux /proc sockets and pseudonymize remote addresses before return."""
    if platform.system().lower() != "linux" or not Path("/proc/net").is_dir():
        raise DiagnosticError("network diagnostics are currently supported only on Linux /proc hosts")
    if len(privacy_key) < 32:
        raise DiagnosticError("network privacy key is too short")

    rows: list[dict[str, Any]] = []
    for protocol, family, path in _PROC_TABLES:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            try:
                local_address, local_port = _endpoint(fields[1], family)
                remote_address, remote_port = _endpoint(fields[2], family)
            except DiagnosticError:
                continue
            state_code = fields[3].upper()
            remote_scope = _scope(remote_address)
            remote_unspecified = remote_scope == "unspecified" and remote_port == 0
            rows.append(
                {
                    "protocol": protocol,
                    "family": family,
                    "local_scope": _scope(local_address),
                    "local_port": local_port,
                    "remote_scope": remote_scope,
                    "remote_port": remote_port,
                    "remote_address_hmac_sha256": None
                    if remote_unspecified
                    else _address_pseudonym(remote_address, privacy_key),
                    "state": _TCP_STATES.get(state_code, state_code.lower())
                    if protocol == "tcp"
                    else state_code.lower(),
                }
            )

    rows.sort(
        key=lambda item: (
            str(item["protocol"]),
            str(item["family"]),
            int(item["local_port"]),
            int(item["remote_port"]),
            str(item["remote_address_hmac_sha256"] or ""),
        )
    )
    return {
        "read_only": True,
        "system_state_changed": False,
        "platform": "Linux",
        "connections": rows[:MAX_NETWORK_RESULTS],
        "truncated": len(rows) > MAX_NETWORK_RESULTS,
        "raw_network_addresses_returned": False,
        "remote_address_identity": "agent_secret_derived_hmac_sha256_128",
    }
