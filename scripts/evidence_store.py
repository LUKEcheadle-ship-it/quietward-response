from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import platform
import stat
import tempfile
import re
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


EVIDENCE_FORMAT = "quietward-response-evidence-store-v1"
EVIDENCE_TTL_MINUTES = 30
MAX_EVIDENCE_ENTRIES = 2048
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
_PROCESS_HANDLE_PREFIX = "qwrp-"


class EvidenceStoreError(RuntimeError):
    pass


def _utc_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise EvidenceStoreError("evidence timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, OverflowError) as exc:
        raise EvidenceStoreError("evidence timestamp is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceStoreError("evidence timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_EVIDENCE_BYTES:
        raise EvidenceStoreError("evidence store exceeds the size limit")
    # mkstemp is exclusive-create and binary by default on Windows. Do not use a
    # predictable .tmp pathname which could already be a symlink to another file.
    descriptor, temporary_name = tempfile.mkstemp(prefix=".qwr-evidence-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise EvidenceStoreError("evidence store must not be a symlink")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _boot_identity() -> str:
    if platform.system().lower() != "linux":
        # Windows creation times are absolute FILETIME values, not time-since-boot.
        return "absolute-process-creation-time"
    try:
        identity = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise EvidenceStoreError("Linux boot identity is unavailable") from exc
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", identity):
        raise EvidenceStoreError("Linux boot identity is invalid")
    return identity


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
        if not isinstance(key, bytes) or len(key) < 32:
            raise EvidenceStoreError("evidence handle key is too short")
        self.path = state_dir.resolve() / "response-agent-evidence.json"
        self.key = key

    def _load(self) -> dict[str, Any]:
        if self.path.is_symlink():
            raise EvidenceStoreError("evidence store must not be a symlink")
        if not self.path.exists():
            return {"format": EVIDENCE_FORMAT, "entries": {}}
        try:
            flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
            descriptor = os.open(self.path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise EvidenceStoreError("evidence store is not a regular file")
                data = stream.read(MAX_EVIDENCE_BYTES + 1)
            if len(data) > MAX_EVIDENCE_BYTES:
                raise EvidenceStoreError("evidence store exceeds the size limit")
            value = json.loads(data.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
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
        try:
            _atomic_json(self.path, {"format": EVIDENCE_FORMAT, "entries": dict(retained)})
        except OSError as exc:
            raise EvidenceStoreError("evidence store could not be saved") from exc

    def _handle_for(self, canonical: str) -> str:
        token = hmac.new(
            self.key,
            ("quietward-response-process-evidence-v1:" + canonical).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:32]
        return _PROCESS_HANDLE_PREFIX + token

    def _record_signature(self, handle: str, record: dict[str, Any]) -> str:
        body = {key: value for key, value in record.items() if key != "record_hmac_sha256"}
        payload = json.dumps(
            {"handle": handle, "record": body}, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        return hmac.new(self.key, b"qwr-process-record-v2:" + payload, hashlib.sha256).hexdigest()

    def _verify_record(self, handle: str, raw: dict[str, Any]) -> None:
        signature = raw.get("record_hmac_sha256")
        if raw.get("record_auth_version") != 2 or not isinstance(signature, str):
            raise EvidenceStoreError("unsigned legacy evidence; collect a fresh triage bundle")
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            raise EvidenceStoreError("evidence record authentication failed")
        try:
            expected = self._record_signature(handle, raw)
        except (TypeError, ValueError) as exc:
            raise EvidenceStoreError("evidence record authentication failed") from exc
        if not hmac.compare_digest(signature, expected):
            raise EvidenceStoreError("evidence record authentication failed")
        now = datetime.now(timezone.utc)
        created, expires = _parse_time(raw.get("created_at")), _parse_time(raw.get("expires_at"))
        if created > now or expires <= created or expires - created > timedelta(minutes=EVIDENCE_TTL_MINUTES):
            raise EvidenceStoreError("evidence record lifetime is invalid")
        if expires <= now:
            raise EvidenceStoreError("process evidence handle has expired")
        if raw.get("boot_identity") != _boot_identity():
            raise EvidenceStoreError("evidence was collected before a reboot or on another platform")

    def record_process(self, row: dict[str, Any]) -> str | None:
        if not isinstance(row, dict):
            return None
        pid, parent_pid, image = row.get("pid"), row.get("parent_pid"), row.get("image")
        if (type(pid) is not int or type(parent_pid) is not int or pid <= 0
                or parent_pid < 0 or not isinstance(image, str) or not 0 < len(image) <= 128):
            return None
        start_marker = process_start_marker(pid)
        if start_marker is None:
            return None
        canonical = f"{pid}|{parent_pid}|{image.casefold()}|{start_marker}"
        handle = self._handle_for(canonical)
        now = datetime.now(timezone.utc)
        value = self._load()
        record = {
            "kind": "process",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=EVIDENCE_TTL_MINUTES)).isoformat(),
            "locator": {"pid": pid},
            "fingerprint": {"parent_pid": parent_pid, "image": image, "start_marker": start_marker},
            "record_auth_version": 2,
            "boot_identity": _boot_identity(),
        }
        record["record_hmac_sha256"] = self._record_signature(handle, record)
        value["entries"][handle] = record
        self._save(value)
        return handle

    def resolve_process(self, handle: str, current_rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not is_process_evidence_handle(handle):
            raise EvidenceStoreError("process evidence handle is invalid")
        value = self._load()
        raw = value["entries"].get(handle)
        if not isinstance(raw, dict) or raw.get("kind") != "process":
            raise EvidenceStoreError("process evidence handle is unknown")
        self._verify_record(handle, raw)
        locator, fingerprint = raw.get("locator"), raw.get("fingerprint")
        if not isinstance(locator, dict) or not isinstance(fingerprint, dict):
            raise EvidenceStoreError("process evidence record is malformed")
        pid = locator.get("pid")
        expected_parent = fingerprint.get("parent_pid")
        expected_image = fingerprint.get("image")
        expected_start = fingerprint.get("start_marker")
        if (type(pid) is not int or pid <= 0 or type(expected_parent) is not int
                or expected_parent < 0 or not isinstance(expected_image, str)
                or not 0 < len(expected_image) <= 128 or not isinstance(expected_start, str)):
            raise EvidenceStoreError("process evidence record is malformed")
        canonical = f"{pid}|{expected_parent}|{expected_image.casefold()}|{expected_start}"
        if not hmac.compare_digest(handle, self._handle_for(canonical)):
            raise EvidenceStoreError("process evidence handle does not match its record")
        if not isinstance(current_rows, list):
            raise EvidenceStoreError("current process inventory is invalid")
        matches = [row for row in current_rows if isinstance(row, dict)
                   and type(row.get("pid")) is int and row["pid"] == pid]
        if not matches:
            raise EvidenceStoreError("evidence-bound process is no longer running")
        if len(matches) != 1:
            raise EvidenceStoreError("evidence-bound process inventory is ambiguous")
        current = matches[0]
        if type(current.get("parent_pid")) is not int or current["parent_pid"] != expected_parent:
            raise EvidenceStoreError("evidence-bound process parent identity changed")
        if not isinstance(current.get("image"), str) or current["image"].casefold() != expected_image.casefold():
            raise EvidenceStoreError("evidence-bound process image identity changed")
        current_start = process_start_marker(pid)
        if current_start is None or current_start != expected_start:
            raise EvidenceStoreError("evidence-bound process instance changed")
        return {
            "pid": pid, "parent_pid": expected_parent, "image": expected_image,
            "start_marker": expected_start, "evidence_handle": handle,
        }
