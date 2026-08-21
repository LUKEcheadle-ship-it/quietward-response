from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import secrets
import shutil
import signal
import stat
import time
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


HANDLE_TTL_SECONDS = 300
ROLLBACK_HANDLE_TTL_SECONDS = 86_400
MAX_PROCESS_RESULTS = 128
MAX_FILE_RESULTS = 128
MAX_FILE_WALK_DIRECTORIES = 256


class ResourceError(RuntimeError):
    pass


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short resource-state write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _load_mapping(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResourceError(f"resource handle state is unreadable or invalid: {path.name}") from exc
    if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
        raise ResourceError("resource handle state has invalid structure")
    return value


class ResourceHandleStore:
    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / "response-agent-resource-handles.json"

    def _load(self) -> dict[str, dict[str, Any]]:
        records = _load_mapping(self.path)
        now = time.time()
        changed = False
        for handle, record in list(records.items()):
            expires_at = float(record.get("expires_at_epoch") or 0)
            consumed_epoch = float(record.get("consumed_at_epoch") or 0)
            old_expired = bool(expires_at and expires_at <= now - 86_400)
            old_consumed = bool(consumed_epoch and consumed_epoch <= now - 86_400)
            if old_expired or old_consumed:
                records.pop(handle, None)
                changed = True
        if changed:
            _atomic_json(self.path, records)
        return records

    def issue(
        self,
        *,
        kind: str,
        identity: dict[str, Any],
        fingerprint: str,
        display: dict[str, Any],
        ttl_seconds: int = HANDLE_TTL_SECONDS,
        preferred_handle: str | None = None,
    ) -> dict[str, Any]:
        ttl = max(30, min(86_400, int(ttl_seconds)))
        records = self._load()
        handle = preferred_handle or ("qwrh1_" + secrets.token_urlsafe(24))
        existing = records.get(handle)
        if existing is not None:
            if existing.get("kind") != kind or existing.get("fingerprint") != fingerprint:
                raise ResourceError("deterministic resource handle collided with different identity")
            return {
                "resource_handle": handle,
                "resource_kind": kind,
                "expires_at": datetime.fromtimestamp(
                    float(existing["expires_at_epoch"]), timezone.utc
                ).isoformat(),
            }
        expires_epoch = time.time() + ttl
        records[handle] = {
            "kind": kind,
            "identity": identity,
            "fingerprint": fingerprint,
            "display": display,
            "issued_at": _utc_now_text(),
            "expires_at_epoch": expires_epoch,
            "consumed_at": None,
            "consumed_at_epoch": None,
            "consumption_result": None,
        }
        _atomic_json(self.path, records)
        return {
            "resource_handle": handle,
            "resource_kind": kind,
            "expires_at": datetime.fromtimestamp(expires_epoch, timezone.utc).isoformat(),
        }

    def inspect(self, handle: str, *, kind: str) -> dict[str, Any]:
        if not isinstance(handle, str) or not handle.startswith("qwrh1_") or len(handle) > 96:
            raise ResourceError("resource handle is malformed")
        record = self._load().get(handle)
        if record is None:
            raise ResourceError("resource handle is unknown or expired")
        if record.get("kind") != kind:
            raise ResourceError("resource handle kind does not match action")
        return dict(record)

    def resolve(self, handle: str, *, kind: str) -> dict[str, Any]:
        record = self.inspect(handle, kind=kind)
        if record.get("consumed_at"):
            raise ResourceError("resource handle has already been consumed")
        if float(record.get("expires_at_epoch") or 0) <= time.time():
            raise ResourceError("resource handle has expired")
        return record

    def consumed_result(self, handle: str, *, kind: str) -> dict[str, Any] | None:
        record = self.inspect(handle, kind=kind)
        result = record.get("consumption_result")
        return dict(result) if record.get("consumed_at") and isinstance(result, dict) else None

    def consume(self, handle: str, result: dict[str, Any]) -> None:
        records = self._load()
        record = records.get(handle)
        if record is None:
            raise ResourceError("resource handle disappeared before completion")
        if record.get("consumed_at"):
            stored = record.get("consumption_result")
            if stored != result:
                raise ResourceError("consumed resource handle result conflict")
            return
        record["consumed_at"] = _utc_now_text()
        record["consumed_at_epoch"] = time.time()
        record["consumption_result"] = result
        records[handle] = record
        _atomic_json(self.path, records)


# ----- Process resources ----------------------------------------------------


def _fingerprint(parts: Iterable[Any]) -> str:
    raw = "|".join(str(item) for item in parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def _linux_process(pid: int) -> dict[str, Any] | None:
    proc = Path("/proc") / str(pid)
    try:
        stat_text = (proc / "stat").read_text(encoding="utf-8", errors="replace")
        close = stat_text.rfind(")")
        open_paren = stat_text.find("(")
        if close < 0 or open_paren < 0:
            return None
        name = stat_text[open_paren + 1 : close][:128]
        fields = stat_text[close + 2 :].split()
        if len(fields) < 20:
            return None
        parent_pid = int(fields[1])
        start_ticks = fields[19]
        try:
            exe_path = os.readlink(proc / "exe")
            executable = Path(exe_path).name[:128]
            inode = os.stat(proc / "exe", follow_symlinks=True).st_ino
        except OSError:
            exe_path = ""
            executable = name
            inode = 0
        fingerprint = _fingerprint((pid, start_ticks, inode, exe_path, name))
        return {
            "pid": pid,
            "parent_pid": parent_pid,
            "image": executable or name or "unknown",
            "fingerprint": fingerprint,
            "identity": {
                "pid": pid,
                "start_ticks": start_ticks,
                "inode": inode,
                "exe_path": exe_path,
                "name": name,
            },
        }
    except (OSError, ValueError):
        return None


def _windows_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_processes() -> list[dict[str, Any]]:
    if os.name != "nt":
        return []
    kernel32 = _windows_kernel32()
    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
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

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    snapshot_value = ctypes.cast(snapshot, ctypes.c_void_p).value
    if snapshot_value == invalid_handle:
        raise ResourceError("Windows process snapshot failed")
    result: list[dict[str, Any]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            parent = int(entry.th32ParentProcessID)
            image = str(entry.szExeFile)[:128]
            creation = 0
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    creation_ft = wintypes.FILETIME()
                    exit_ft = wintypes.FILETIME()
                    kernel_ft = wintypes.FILETIME()
                    user_ft = wintypes.FILETIME()
                    if kernel32.GetProcessTimes(
                        handle,
                        ctypes.byref(creation_ft),
                        ctypes.byref(exit_ft),
                        ctypes.byref(kernel_ft),
                        ctypes.byref(user_ft),
                    ):
                        creation = (int(creation_ft.dwHighDateTime) << 32) | int(
                            creation_ft.dwLowDateTime
                        )
                finally:
                    kernel32.CloseHandle(handle)
            fingerprint = _fingerprint((pid, parent, image.lower(), creation))
            result.append(
                {
                    "pid": pid,
                    "parent_pid": parent,
                    "image": image or "unknown",
                    "fingerprint": fingerprint,
                    "identity": {
                        "pid": pid,
                        "parent_pid": parent,
                        "image": image,
                        "creation_filetime": creation,
                    },
                }
            )
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def sys_platform() -> str:
    return platform.system().lower()


def _processes() -> list[dict[str, Any]]:
    if os.name == "nt":
        return _windows_processes()
    if sys_platform() == "linux":
        result = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            item = _linux_process(int(entry.name))
            if item is not None:
                result.append(item)
        return result
    raise ResourceError("process diagnostics are supported only on Windows and Linux")


def _protected_process(item: dict[str, Any]) -> bool:
    pid = int(item.get("pid") or 0)
    image = str(item.get("image") or "").lower()
    if pid in {0, 1, 2, 4, os.getpid(), os.getppid()}:
        return True
    if os.name == "nt" and image in {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
    }:
        return True
    return False


def collect_process_diagnostic(store: ResourceHandleStore) -> dict[str, Any]:
    all_records = sorted(_processes(), key=lambda item: int(item["pid"]))
    records = all_records[:MAX_PROCESS_RESULTS]
    returned: list[dict[str, Any]] = []
    for item in records:
        protected = _protected_process(item)
        row = {
            "pid": item["pid"],
            "parent_pid": item["parent_pid"],
            "image": item["image"],
            "protected": protected,
        }
        if not protected:
            row.update(
                store.issue(
                    kind="process",
                    identity=dict(item["identity"]),
                    fingerprint=str(item["fingerprint"]),
                    display={
                        "pid": item["pid"],
                        "parent_pid": item["parent_pid"],
                        "image": item["image"],
                    },
                )
            )
        returned.append(row)
    return {
        "read_only": True,
        "system_state_changed": False,
        "resource_handle_ttl_seconds": HANDLE_TTL_SECONDS,
        "processes": returned,
        "truncated": len(all_records) > MAX_PROCESS_RESULTS,
    }


def _current_process(identity: dict[str, Any]) -> dict[str, Any] | None:
    pid = int(identity.get("pid") or -1)
    if pid < 0:
        return None
    if os.name == "nt":
        return next((item for item in _windows_processes() if item["pid"] == pid), None)
    if sys_platform() == "linux":
        return _linux_process(pid)
    return None


def terminate_process_by_handle(
    store: ResourceHandleStore,
    handle: str,
    *,
    recover_after_started: bool = False,
) -> dict[str, Any]:
    prior = store.consumed_result(handle, kind="process")
    if prior is not None:
        return prior
    record = store.resolve(handle, kind="process")
    identity = dict(record.get("identity") or {})
    current = _current_process(identity)
    if current is None or current["fingerprint"] != record.get("fingerprint"):
        if not recover_after_started:
            if current is None:
                raise ResourceError("process no longer exists")
            raise ResourceError("process identity changed after handle issuance")
        result = {
            "resource_handle": handle,
            "pid": int(identity.get("pid") or -1),
            "image": str(record.get("display", {}).get("image") or "unknown"),
            "termination_requested": True,
            "original_process_no_longer_present": True,
            "replacement_process_was_not_touched": current is not None,
            "system_state_changed": True,
            "reversible": False,
            "recovered_after_interruption": True,
        }
        store.consume(handle, result)
        return result
    if _protected_process(current):
        raise ResourceError("process is protected from Response termination")
    pid = int(current["pid"])

    if os.name == "nt":
        kernel32 = _windows_kernel32()
        PROCESS_TERMINATE = 0x0001
        process_handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not process_handle:
            raise ResourceError("Windows denied process termination handle")
        try:
            if not kernel32.TerminateProcess(process_handle, 1):
                raise ResourceError("Windows process termination failed")
        finally:
            kernel32.CloseHandle(process_handle)
    else:
        os.kill(pid, signal.SIGTERM)

    result = {
        "resource_handle": handle,
        "pid": pid,
        "image": current["image"],
        "termination_requested": True,
        "signal": "TerminateProcess" if os.name == "nt" else "SIGTERM",
        "system_state_changed": True,
        "reversible": False,
    }
    store.consume(handle, result)
    return result


# ----- Managed-file resources ---------------------------------------------


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _file_identity(path: Path, root: Path) -> tuple[dict[str, Any], str, dict[str, Any]]:
    if path.is_symlink():
        raise ResourceError("symbolic links are not eligible for managed file actions")
    resolved = path.resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if not _within(resolved, resolved_root):
        raise ResourceError("managed file escaped configured root")
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ResourceError("managed file action requires a regular file")
    identity = {
        "path": str(resolved),
        "root": str(resolved_root),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
    }
    fingerprint = _fingerprint(identity.values())
    display = {
        "root": resolved_root.name or str(resolved_root),
        "relative_path": resolved.relative_to(resolved_root).as_posix(),
        "size": int(info.st_size),
        "modified_at": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat(),
    }
    return identity, fingerprint, display


def collect_file_diagnostic(
    store: ResourceHandleStore,
    managed_roots: tuple[Path, ...],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    visited_directories = 0
    for root in managed_roots:
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        if not resolved_root.is_dir():
            continue
        for directory, dirnames, filenames in os.walk(resolved_root, followlinks=False):
            visited_directories += 1
            if visited_directories > MAX_FILE_WALK_DIRECTORIES:
                break
            dirnames[:] = [
                name
                for name in sorted(dirnames)[:64]
                if not (Path(directory) / name).is_symlink()
            ]
            for filename in sorted(filenames):
                if len(rows) >= MAX_FILE_RESULTS:
                    break
                path = Path(directory) / filename
                try:
                    identity, fingerprint, display = _file_identity(path, resolved_root)
                except (OSError, ResourceError):
                    continue
                row = dict(display)
                row.update(
                    store.issue(
                        kind="managed_file",
                        identity=identity,
                        fingerprint=fingerprint,
                        display=display,
                    )
                )
                rows.append(row)
            if len(rows) >= MAX_FILE_RESULTS:
                break
        if len(rows) >= MAX_FILE_RESULTS or visited_directories > MAX_FILE_WALK_DIRECTORIES:
            break
    return {
        "read_only": True,
        "system_state_changed": False,
        "resource_handle_ttl_seconds": HANDLE_TTL_SECONDS,
        "managed_root_count": len(managed_roots),
        "files": rows,
        "truncated": len(rows) >= MAX_FILE_RESULTS
        or visited_directories > MAX_FILE_WALK_DIRECTORIES,
    }


def _quarantine_target(quarantine_dir: Path, handle: str) -> Path:
    name = "quarantined-" + hashlib.sha256(handle.encode("utf-8")).hexdigest()[:24]
    return quarantine_dir / name


def _rollback_handle(handle: str) -> str:
    return "qwrh1_rb_" + hashlib.sha256(handle.encode("utf-8")).hexdigest()[:40]


def quarantine_file_by_handle(
    store: ResourceHandleStore,
    handle: str,
    quarantine_dir: Path,
    *,
    recover_after_started: bool = False,
) -> dict[str, Any]:
    prior = store.consumed_result(handle, kind="managed_file")
    if prior is not None:
        return prior
    record = store.resolve(handle, kind="managed_file")
    identity = dict(record.get("identity") or {})
    path = Path(str(identity.get("path") or ""))
    root = Path(str(identity.get("root") or ""))
    quarantine_dir = quarantine_dir.resolve()
    quarantine_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = _quarantine_target(quarantine_dir, handle)

    recovered = False
    if not path.exists():
        if not recover_after_started or not target.exists() or not target.is_file():
            raise ResourceError("managed file disappeared before quarantine")
        display = dict(record.get("display") or {})
        recovered = True
    else:
        current_identity, fingerprint, display = _file_identity(path, root)
        if fingerprint != record.get("fingerprint"):
            raise ResourceError("file identity changed after handle issuance")
        if target.exists():
            raise ResourceError("quarantine target already exists while source still exists")
        shutil.move(str(path), str(target))
        identity = current_identity

    target_info = target.stat()
    rollback_identity = {
        "original_path": str(path),
        "quarantine_path": str(target),
        "root": str(root),
    }
    rollback_fingerprint = _fingerprint(
        (str(target), int(target_info.st_size), int(target_info.st_mtime_ns))
    )
    rollback = store.issue(
        kind="quarantined_file",
        identity=rollback_identity,
        fingerprint=rollback_fingerprint,
        display={"relative_path": display.get("relative_path", path.name)},
        ttl_seconds=ROLLBACK_HANDLE_TTL_SECONDS,
        preferred_handle=_rollback_handle(handle),
    )
    result = {
        "resource_handle": handle,
        "quarantined": True,
        "system_state_changed": True,
        "reversible": True,
        "original_relative_path": display.get("relative_path", path.name),
        "rollback_resource_handle": rollback["resource_handle"],
        "rollback_expires_at": rollback["expires_at"],
        "recovered_after_interruption": recovered,
    }
    store.consume(handle, result)
    return result


def restore_quarantined_file(
    store: ResourceHandleStore,
    handle: str,
    *,
    recover_after_started: bool = False,
) -> dict[str, Any]:
    prior = store.consumed_result(handle, kind="quarantined_file")
    if prior is not None:
        return prior
    record = store.resolve(handle, kind="quarantined_file")
    identity = dict(record.get("identity") or {})
    source = Path(str(identity.get("quarantine_path") or ""))
    destination = Path(str(identity.get("original_path") or ""))
    root = Path(str(identity.get("root") or ""))

    recovered = False
    if not source.exists():
        if not recover_after_started or not destination.exists() or not destination.is_file():
            raise ResourceError("quarantined file no longer exists")
        recovered = True
    else:
        if destination.exists():
            raise ResourceError("original path is occupied; refusing restore")
        try:
            resolved_parent = destination.parent.resolve(strict=True)
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise ResourceError("restore parent/root is unavailable") from exc
        if not _within(resolved_parent, resolved_root):
            raise ResourceError("restore target escaped configured managed root")
        current_fingerprint = _fingerprint(
            (str(source), int(source.stat().st_size), int(source.stat().st_mtime_ns))
        )
        if current_fingerprint != record.get("fingerprint"):
            raise ResourceError("quarantined file changed after quarantine")
        shutil.move(str(source), str(destination))

    try:
        resolved_root = root.resolve(strict=True)
        relative = destination.resolve(strict=True).relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        relative = destination.name
    result = {
        "rollback_resource_handle": handle,
        "restored": True,
        "system_state_changed": True,
        "restored_relative_path": relative,
        "recovered_after_interruption": recovered,
    }
    store.consume(handle, result)
    return result


# ----- Host diagnostic -----------------------------------------------------


def collect_host_diagnostic(state_dir: Path) -> dict[str, Any]:
    disk = shutil.disk_usage(state_dir)
    uptime_seconds: float | None = None
    if sys_platform() == "linux":
        try:
            uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            uptime_seconds = None
    load_average: tuple[float, float, float] | None = None
    if hasattr(os, "getloadavg"):
        try:
            load_average = tuple(round(value, 3) for value in os.getloadavg())
        except OSError:
            load_average = None
    return {
        "read_only": True,
        "system_state_changed": False,
        "platform": platform.system(),
        "platform_release": platform.release()[:128],
        "machine": platform.machine()[:64],
        "cpu_count": os.cpu_count(),
        "uptime_seconds": uptime_seconds,
        "load_average": list(load_average) if load_average else None,
        "agent_state_disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
        },
    }
