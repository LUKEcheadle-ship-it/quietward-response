from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

try:  # package-style qualification import
    from scripts import response_agent_resources as resources
except ImportError:  # direct script/runtime import
    import response_agent_resources as resources

FILE_DIAGNOSTIC_BYTE_BUDGET = 256 * 1024 * 1024


def collect_file_diagnostic(
    store: resources.ResourceHandleStore,
    managed_roots: tuple[Path, ...],
    *,
    byte_budget: int = FILE_DIAGNOSTIC_BYTE_BUDGET,
) -> dict[str, Any]:
    budget = max(1, min(int(byte_budget), FILE_DIAGNOSTIC_BYTE_BUDGET))
    rows: list[dict[str, Any]] = []
    visited_directories = 0
    skipped_oversize = 0
    skipped_budget = 0
    scanned_bytes = 0
    budget_exhausted = False

    for root in managed_roots:
        try:
            resolved_root = root.resolve(strict=True)
        except OSError:
            continue
        if not resolved_root.is_dir():
            continue
        for directory, dirnames, filenames in os.walk(resolved_root, followlinks=False):
            visited_directories += 1
            if visited_directories > resources.MAX_FILE_WALK_DIRECTORIES:
                break
            dirnames[:] = [
                name
                for name in sorted(dirnames)[:64]
                if not (Path(directory) / name).is_symlink()
            ]
            for filename in sorted(filenames):
                if len(rows) >= resources.MAX_FILE_RESULTS:
                    break
                path = Path(directory) / filename
                try:
                    before = path.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                    continue
                size = int(before.st_size)
                if size > resources.MAX_MANAGED_FILE_BYTES:
                    skipped_oversize += 1
                    continue
                if scanned_bytes + size > budget:
                    skipped_budget += 1
                    budget_exhausted = True
                    break
                try:
                    identity, fingerprint, display = resources._file_identity(
                        path,
                        resolved_root,
                    )
                except resources.ResourceError as exc:
                    if "exceeds v1.2 handle size limit" in str(exc):
                        skipped_oversize += 1
                    continue
                except OSError:
                    continue
                scanned_bytes += int(identity.get("size") or 0)
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
            if (
                len(rows) >= resources.MAX_FILE_RESULTS
                or visited_directories > resources.MAX_FILE_WALK_DIRECTORIES
                or budget_exhausted
            ):
                break
        if (
            len(rows) >= resources.MAX_FILE_RESULTS
            or visited_directories > resources.MAX_FILE_WALK_DIRECTORIES
            or budget_exhausted
        ):
            break

    return {
        "read_only": True,
        "system_state_changed": False,
        "resource_handle_ttl_seconds": resources.HANDLE_TTL_SECONDS,
        "managed_file_max_bytes": resources.MAX_MANAGED_FILE_BYTES,
        "scan_byte_budget": budget,
        "scanned_bytes": scanned_bytes,
        "managed_root_count": len(managed_roots),
        "files": rows,
        "skipped_oversize_files": skipped_oversize,
        "skipped_due_to_byte_budget": skipped_budget,
        "truncated": (
            len(rows) >= resources.MAX_FILE_RESULTS
            or visited_directories > resources.MAX_FILE_WALK_DIRECTORIES
            or budget_exhausted
        ),
    }
