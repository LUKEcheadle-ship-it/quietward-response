from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.main import _load_trusted_audit_checkpoint


def _checkpoint(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": "2026-08-21T18:00:00+00:00",
                "entries_checked": 1,
                "head_hash": "0" * 64,
                "signature": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode/symlink policy")
def test_group_or_world_writable_checkpoint_is_rejected(tmp_path: Path) -> None:
    path = _checkpoint(tmp_path / "writable-checkpoint.json")
    path.chmod(0o666)
    with pytest.raises(RuntimeError, match="must not be group/world writable"):
        _load_trusted_audit_checkpoint(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode/symlink policy")
def test_private_or_read_only_checkpoint_is_accepted_by_file_safety_layer(tmp_path: Path) -> None:
    path = _checkpoint(tmp_path / "private-checkpoint.json")
    path.chmod(0o600)
    loaded = _load_trusted_audit_checkpoint(path)
    assert loaded["schema_version"] == "1.0"

    path.chmod(0o444)
    loaded = _load_trusted_audit_checkpoint(path)
    assert loaded["entries_checked"] == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_symlink_checkpoint_is_rejected_even_when_target_is_private(tmp_path: Path) -> None:
    target = _checkpoint(tmp_path / "real-checkpoint.json")
    target.chmod(0o600)
    link = tmp_path / "checkpoint-link.json"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="must not be a symbolic link"):
        _load_trusted_audit_checkpoint(link)


def test_oversized_checkpoint_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "oversized-checkpoint.json"
    path.write_text(json.dumps({"padding": "x" * 20_000}), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    with pytest.raises(RuntimeError, match="unexpectedly large"):
        _load_trusted_audit_checkpoint(path)
