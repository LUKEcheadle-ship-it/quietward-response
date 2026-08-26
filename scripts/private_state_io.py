from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
DEFAULT_MAX_STATE_BYTES = 64 * 1024 * 1024


class PrivateStateError(RuntimeError):
    pass


def _link_like(details: os.stat_result) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(
        attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return (
        left.st_dev,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _private_parent(path: Path) -> Path:
    if not path.is_absolute():
        raise PrivateStateError("private state path must be absolute")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = parent.lstat()
    except OSError as exc:
        raise PrivateStateError("private state directory is unavailable") from exc
    if _link_like(info) or not stat.S_ISDIR(info.st_mode):
        raise PrivateStateError("private state directory must be a normal directory")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        try:
            parent.chmod(0o700)
            info = parent.lstat()
        except OSError as exc:
            raise PrivateStateError("private state directory permissions are unsafe") from exc
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise PrivateStateError("private state directory permissions are unsafe")
    return parent


def atomic_private_json(path: Path, value: Any) -> None:
    target = path.expanduser()
    parent = _private_parent(target)
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = parent / f".{target.name}.tmp-{os.getpid()}-{secrets.token_hex(12)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("private state write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, target)
        try:
            target.chmod(0o600)
        except OSError:
            pass
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def load_private_json(
    path: Path,
    expected_type: type,
    *,
    max_bytes: int = DEFAULT_MAX_STATE_BYTES,
) -> Any:
    target = path.expanduser()
    if not target.is_absolute():
        raise PrivateStateError("private state path must be absolute")
    if not target.exists():
        return expected_type()
    try:
        before = target.lstat()
    except OSError as exc:
        raise PrivateStateError("private state file is unavailable") from exc
    if (
        _link_like(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or before.st_size > max_bytes
    ):
        raise PrivateStateError("private state file must be a bounded regular file")
    if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o077:
        raise PrivateStateError("private state file must not be group/world accessible")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(target, flags)
    except OSError as exc:
        raise PrivateStateError("private state file could not be opened safely") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            _link_like(opened)
            or not stat.S_ISREG(opened.st_mode)
            or not _same_file(before, opened)
        ):
            raise PrivateStateError("private state file changed during validation")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise PrivateStateError("private state file exceeds the size limit")
            chunks.append(chunk)
    finally:
        os.close(descriptor)

    try:
        after = target.lstat()
    except OSError as exc:
        raise PrivateStateError("private state file disappeared during read") from exc
    if _link_like(after) or not _same_file(before, after):
        raise PrivateStateError("private state file changed during read")
    try:
        value = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrivateStateError("private state file contains invalid JSON") from exc
    if not isinstance(value, expected_type):
        raise PrivateStateError("private state file has invalid structure")
    return value
