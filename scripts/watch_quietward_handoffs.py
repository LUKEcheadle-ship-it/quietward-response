#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ingest_quietward_handoff import HandoffError, _post_event, _validate_event
from response_agent import AgentConfig


MAX_HANDOFF_BYTES = 2_000_000
MAX_FILES_PER_PASS = 256
MAX_LEDGER_ENTRIES = 8192
DEFAULT_ARCHIVE_FILES = 512
_CHAIN_HASH = re.compile(r"^[0-9a-f]{64}$")


class HandoffWatcherError(RuntimeError):
    pass


def _private_directory(path: Path, *, create: bool) -> Path:
    resolved = path.expanduser().resolve()
    if create:
        resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not resolved.exists() or resolved.is_symlink() or not resolved.is_dir():
        raise HandoffWatcherError(f"handoff directory is unavailable or unsafe: {resolved}")
    if os.name != "nt":
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if mode & 0o077:
            try:
                resolved.chmod(0o700)
            except OSError as exc:
                raise HandoffWatcherError(f"handoff directory permissions are unsafe: {resolved}") from exc
    return resolved


def _safe_bytes(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise HandoffWatcherError(f"handoff file is unavailable: {path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise HandoffWatcherError(f"handoff file must be a normal file: {path.name}")
    if info.st_size < 2 or info.st_size > MAX_HANDOFF_BYTES:
        raise HandoffWatcherError(f"handoff file size is outside the allowed bounds: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise HandoffWatcherError(f"handoff file could not be opened safely: {path.name}") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise HandoffWatcherError(f"handoff file changed type while opening: {path.name}")
        chunks: list[bytes] = []
        remaining = MAX_HANDOFF_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(data) > MAX_HANDOFF_BYTES:
        raise HandoffWatcherError(f"handoff file exceeded the read bound: {path.name}")
    try:
        after = path.lstat()
    except OSError as exc:
        raise HandoffWatcherError(f"handoff file changed during read: {path.name}") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or not stat.S_ISREG(after.st_mode)
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
    ):
        raise HandoffWatcherError(f"handoff file changed during read: {path.name}")
    return data


def _document(data: bytes, config: AgentConfig) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise HandoffWatcherError("handoff file contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise HandoffWatcherError("handoff document root must be an object")
    required_keys = {
        "format",
        "generated_at",
        "source_version",
        "source_cycle_id",
        "source_chain_hash",
        "host_ids",
        "events",
        "safety",
    }
    if set(value) != required_keys:
        raise HandoffWatcherError("outbox handoff document contains unexpected root fields")
    if value.get("format") != "quietward-response-handoff-v1":
        raise HandoffWatcherError("outbox handoff format is unsupported")
    cycle_id = value.get("source_cycle_id")
    if not isinstance(cycle_id, int) or isinstance(cycle_id, bool) or cycle_id <= 0:
        raise HandoffWatcherError("outbox handoff source cycle is invalid")
    chain_hash = value.get("source_chain_hash")
    if not isinstance(chain_hash, str) or not _CHAIN_HASH.fullmatch(chain_hash):
        raise HandoffWatcherError("outbox handoff evidence-chain hash is invalid")
    host_ids = value.get("host_ids")
    if host_ids != [config.host_id]:
        raise HandoffWatcherError("outbox handoff is not bound to this Response agent host")
    safety = value.get("safety")
    required_safety = {
        "observation_only_source": True,
        "actions_executed": 0,
        "executable_authority": False,
        "raw_finding_subjects_included": False,
        "network_request_performed": False,
    }
    if not isinstance(safety, dict) or safety != required_safety:
        raise HandoffWatcherError("outbox handoff safety declaration is invalid")
    events = value.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 1000:
        raise HandoffWatcherError("outbox handoff must contain 1-1000 events")
    for event in events:
        try:
            _validate_event(event, config)
        except HandoffError as exc:
            raise HandoffWatcherError(str(exc)) from exc
        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            raise HandoffWatcherError("outbox handoff event metadata is invalid")
        if metadata.get("quietward_source_cycle_id") != cycle_id:
            raise HandoffWatcherError("event provenance cycle does not match the outbox document")
        if metadata.get("quietward_source_chain_hash") != chain_hash:
            raise HandoffWatcherError("event provenance hash does not match the outbox document")
    return value


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short handoff watcher ledger write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _ledger_path(config: AgentConfig) -> Path:
    return config.state_dir / "quietward-handoff-consumption-ledger.json"


def _load_ledger(config: AgentConfig) -> dict[str, dict[str, Any]]:
    path = _ledger_path(config)
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffWatcherError("handoff consumption ledger is unreadable") from exc
    if not isinstance(value, dict) or any(not isinstance(item, dict) for item in value.values()):
        raise HandoffWatcherError("handoff consumption ledger is invalid")
    return value


def _save_ledger(config: AgentConfig, ledger: dict[str, dict[str, Any]]) -> None:
    if len(ledger) > MAX_LEDGER_ENTRIES:
        ordered = sorted(
            ledger.items(),
            key=lambda item: str(item[1].get("processed_at") or ""),
        )
        ledger = dict(ordered[-MAX_LEDGER_ENTRIES:])
    _atomic_json(_ledger_path(config), ledger)


def _archive(path: Path, archive_dir: Path, digest: str) -> None:
    destination = archive_dir / path.name
    if destination.exists():
        existing = _safe_bytes(destination)
        if hashlib.sha256(existing).hexdigest() != digest:
            raise HandoffWatcherError(f"archive file name collision: {path.name}")
        path.unlink()
        return
    os.replace(path, destination)
    try:
        destination.chmod(0o600)
    except OSError:
        pass


def _prune_archive(archive_dir: Path, maximum: int) -> None:
    if maximum < 0:
        return
    files = [item for item in archive_dir.glob("cycle-*.json") if item.is_file() and not item.is_symlink()]
    files.sort(key=lambda item: (item.stat().st_mtime_ns, item.name))
    for item in files[:-maximum] if maximum else files:
        try:
            item.unlink()
        except OSError:
            pass


def watch_once(
    config: AgentConfig,
    inbox: Path,
    archive_dir: Path,
    *,
    max_files: int = MAX_FILES_PER_PASS,
    archive_files: int = DEFAULT_ARCHIVE_FILES,
) -> dict[str, int]:
    if not 1 <= max_files <= 1000:
        raise HandoffWatcherError("max files per pass must be between 1 and 1000")
    if not 0 <= archive_files <= 10000:
        raise HandoffWatcherError("archive file retention must be between 0 and 10000")
    resolved_inbox = _private_directory(inbox, create=False)
    resolved_archive = _private_directory(archive_dir, create=True)
    ledger = _load_ledger(config)
    sent = duplicates = skipped = processed = 0

    files = [
        item
        for item in resolved_inbox.glob("cycle-*.json")
        if item.is_file() and not item.is_symlink()
    ]
    files.sort(key=lambda item: item.name)
    for path in files[:max_files]:
        data = _safe_bytes(path)
        digest = hashlib.sha256(data).hexdigest()
        prior = ledger.get(path.name)
        if prior is not None:
            if prior.get("sha256") != digest:
                raise HandoffWatcherError(f"previously processed handoff changed: {path.name}")
            _archive(path, resolved_archive, digest)
            skipped += 1
            continue

        document = _document(data, config)
        file_sent = file_duplicates = 0
        for event in document["events"]:
            try:
                outcome = _post_event(config, event)
            except HandoffError as exc:
                raise HandoffWatcherError(str(exc)) from exc
            file_sent += int(outcome == "sent")
            file_duplicates += int(outcome == "duplicate")

        ledger[path.name] = {
            "sha256": digest,
            "source_cycle_id": int(document["source_cycle_id"]),
            "source_chain_hash": str(document["source_chain_hash"]),
            "events_sent": file_sent,
            "duplicates": file_duplicates,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_ledger(config, ledger)
        _archive(path, resolved_archive, digest)
        sent += file_sent
        duplicates += file_duplicates
        processed += 1

    _prune_archive(resolved_archive, archive_files)
    remaining = len(list(resolved_inbox.glob("cycle-*.json")))
    return {
        "files_processed": processed,
        "events_sent": sent,
        "duplicates": duplicates,
        "already_processed": skipped,
        "remaining_files": remaining,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Continuously consume the local QuietWard handoff outbox using a Response-owned authenticated agent"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--inbox", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--max-files", type=int, default=MAX_FILES_PER_PASS)
    parser.add_argument("--archive-files", type=int, default=DEFAULT_ARCHIVE_FILES)
    args = parser.parse_args()

    if not 1 <= args.interval <= 300:
        raise HandoffWatcherError("poll interval must be between 1 and 300 seconds")
    config = AgentConfig.from_file(args.config)
    inbox = args.inbox.expanduser()
    if not inbox.is_absolute():
        raise HandoffWatcherError("handoff inbox path must be absolute")
    archive_dir = (args.archive_dir or (inbox / "processed")).expanduser()
    if not archive_dir.is_absolute():
        raise HandoffWatcherError("handoff archive path must be absolute")

    while True:
        result = watch_once(
            config,
            inbox,
            archive_dir,
            max_files=args.max_files,
            archive_files=args.archive_files,
        )
        if args.once:
            print(json.dumps(result, sort_keys=True))
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HandoffWatcherError, HandoffError) as exc:
        print(f"QuietWard handoff watcher failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
