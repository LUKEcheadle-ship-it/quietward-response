from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import platform
import stat
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


EVIDENCE_FORMAT = "quietward-response-evidence-store-v1"
EVIDENCE_TTL_MINUTES = 30
MAX_EVIDENCE_ENTRIES = 2048
_PROCESS_HANDLE_PREFIX = "qwrp-"


class EvidenceStoreError(RuntimeError):
    pass


def _utc_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EvidenceStoreError("evidence timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceStoreError("evidence timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short evidence-store write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _linux_process_start_marker(pid: int) -> str | None:
    try:
        text = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return None
    close_paren = text.rfind(")")
    if close_paren < 0:
        return None
    fields = text[close_paren + 2 :].split()
    if len(fields) <= 19:
        return None
    return fields[19]


def _windows_process_start_marker(pid: int) -> str | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
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
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        marker = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
        return str(marker)
    finally:
        kernel32.CloseHandle(handle)


def process_start_marker(pid: int) -> str | None:
    if platform.system().lower() == "linux":
        return _linux_process_start_marker(pid)
    if os.name == "nt":
        return _windows_process_start_marker(pid)
    return None


def is_process_evidence_handle(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(_PROCESS_HANDLE_PREFIX):
        return False
    token = value[len(_PROCESS_HANDLE_PREFIX) :]
    return len(token) == 32 and all(character in "0123456789abcdef" for character in token)


class EvidenceStore:
    """Endpoint-local resolver for opaque evidence handles.

    Raw process locators never need to be supplied by the analyst or QuietWard
    handoff. Response receives only the opaque handle plus the already-bounded
    diagnostic display fields. The agent resolves and revalidates the target locally.
    """

    def __init__(self, state_dir: Path, key: bytes) -> None:
        if len(key) < 32:
            raise EvidenceStoreError("evidence handle key is too short")
        self.path = state_dir.resolve() / "response-agent-evidence.json"
        self.key = key

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"format": EVIDENCE_FORMAT, "entries": {}}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("evidence store is unreadable or invalid") from exc
        if not isinstance(value, dict) or value.get("format") != EVIDENCE_FORMAT:
            raise EvidenceStoreError("evidence store format is invalid")
        entries = value.get("entries")
        if not isinstance(entries, dict):
            raise EvidenceStoreError("evidence store entries are invalid")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        entries = value.get("entries")
        if not isinstance(entries, dict):
            raise EvidenceStoreError("evidence store entries are invalid")
        now = datetime.now(timezone.utc)
        retained: list[tuple[str, dict[str, Any]]] = []
        for handle, raw in entries.items():
            if not isinstance(raw, dict):
                continue
            try:
                expires = _parse_time(raw.get("expires_at"))
            except (EvidenceStoreError, ValueError):
                continue
            if expires > now:
                retained.append((str(handle), raw))
        retained = retained[-MAX_EVIDENCE_ENTRIES:]
        _atomic_json(self.path, {"format": EVIDENCE_FORMAT, "entries": dict(retained)})

    def _handle_for(self, canonical: str) -> str:
        token = hmac.new(
            self.key,
            ("quietward-response-process-evidence-v1:" + canonical).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:32]
        return _PROCESS_HANDLE_PREFIX + token

    def record_process(self, row: dict[str, Any]) -> str | None:
        try:
            pid = int(row["pid"])
            parent_pid = int(row["parent_pid"])
            image = str(row["image"])
        except (KeyError, TypeError, ValueError):
            return None
        if pid <= 0 or not image or len(image) > 128:
            return None
        start_marker = process_start_marker(pid)
        if start_marker is None:
            return None
        canonical = f"{pid}|{parent_pid}|{image.casefold()}|{start_marker}"
        handle = self._handle_for(canonical)
        now = datetime.now(timezone.utc)
        value = self._load()
        entries = value["entries"]
        entries[handle] = {
            "kind": "process",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=EVIDENCE_TTL_MINUTES)).isoformat(),
            "locator": {"pid": pid},
            "fingerprint": {
                "parent_pid": parent_pid,
                "image": image,
                "start_marker": start_marker,
            },
        }
        self._save(value)
        return handle

    def resolve_process(self, handle: str, current_rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not is_process_evidence_handle(handle):
            raise EvidenceStoreError("process evidence handle is invalid")
        value = self._load()
        raw = value["entries"].get(handle)
        if not isinstance(raw, dict) or raw.get("kind") != "process":
            raise EvidenceStoreError("process evidence handle is unknown")
        if _parse_time(raw.get("expires_at")) <= datetime.now(timezone.utc):
            raise EvidenceStoreError("process evidence handle has expired")
        locator = raw.get("locator")
        fingerprint = raw.get("fingerprint")
        if not isinstance(locator, dict) or not isinstance(fingerprint, dict):
            raise EvidenceStoreError("process evidence record is malformed")
        try:
            pid = int(locator["pid"])
            expected_parent = int(fingerprint["parent_pid"])
            expected_image = str(fingerprint["image"])
            expected_start = str(fingerprint["start_marker"])
        except (KeyError, TypeError, ValueError) as exc:
            raise EvidenceStoreError("process evidence record is malformed") from exc
        current = next((row for row in current_rows if int(row.get("pid", -1)) == pid), None)
        if current is None:
            raise EvidenceStoreError("evidence-bound process is no longer running")
        if int(current.get("parent_pid", -1)) != expected_parent:
            raise EvidenceStoreError("evidence-bound process parent identity changed")
        if str(current.get("image") or "").casefold() != expected_image.casefold():
            raise EvidenceStoreError("evidence-bound process image identity changed")
        current_start = process_start_marker(pid)
        if current_start is None or current_start != expected_start:
            raise EvidenceStoreError("evidence-bound process instance changed")
        return {
            "pid": pid,
            "parent_pid": expected_parent,
            "image": expected_image,
            "start_marker": expected_start,
            "evidence_handle": handle,
        }
