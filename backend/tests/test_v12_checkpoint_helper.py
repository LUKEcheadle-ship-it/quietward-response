from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from scripts.manage_audit_checkpoint import (
    CheckpointToolError,
    _atomic_private_json,
    _base_url,
    _load_checkpoint,
    _validate_checkpoint,
)


def _checkpoint() -> dict:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-08-21T18:00:00+00:00",
        "entries_checked": 4,
        "head_hash": "a" * 64,
        "signature": "b" * 64,
    }


def test_checkpoint_helper_allows_loopback_http_and_requires_https_remotely() -> None:
    assert _base_url("http://127.0.0.1:8002/") == "http://127.0.0.1:8002"
    assert _base_url("https://response.example.test/") == "https://response.example.test"
    with pytest.raises(CheckpointToolError, match="plain HTTP.*loopback"):
        _base_url("http://192.0.2.20:8002")
    with pytest.raises(CheckpointToolError, match="must not contain a path"):
        _base_url("https://response.example.test/api/v1")
    with pytest.raises(CheckpointToolError, match="embedded credentials"):
        _base_url("https://analyst:secret@response.example.test")


def test_checkpoint_shape_validation_is_strict() -> None:
    _validate_checkpoint(_checkpoint())

    extra = {**_checkpoint(), "unexpected": True}
    with pytest.raises(CheckpointToolError, match="unexpected field set"):
        _validate_checkpoint(extra)

    bad_digest = {**_checkpoint(), "signature": "not-a-digest"}
    with pytest.raises(CheckpointToolError, match="64-character digest"):
        _validate_checkpoint(bad_digest)


def test_atomic_checkpoint_export_is_private_and_does_not_contain_token(tmp_path: Path) -> None:
    output = (tmp_path / "retained-checkpoint.json").resolve()
    written = _atomic_private_json(output, _checkpoint(), force=False)
    assert written == output
    stored = json.loads(output.read_text(encoding="utf-8"))
    assert stored == _checkpoint()
    assert "bearer" not in output.read_text(encoding="utf-8").lower()
    if os.name != "nt":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600

    with pytest.raises(CheckpointToolError, match="already exists"):
        _atomic_private_json(output, _checkpoint(), force=False)


def test_load_checkpoint_rejects_relative_symlink_and_oversize(tmp_path: Path) -> None:
    with pytest.raises(CheckpointToolError, match="must be absolute"):
        _load_checkpoint(Path("relative.json"))

    valid = (tmp_path / "valid.json").resolve()
    _atomic_private_json(valid, _checkpoint(), force=False)
    assert _load_checkpoint(valid) == _checkpoint()

    if os.name != "nt":
        link = (tmp_path / "link.json").resolve()
        link.symlink_to(valid)
        with pytest.raises(CheckpointToolError, match="symbolic link"):
            _load_checkpoint(link)

    oversized = (tmp_path / "oversized.json").resolve()
    oversized.write_text(json.dumps({"padding": "x" * 20_000}), encoding="utf-8")
    with pytest.raises(CheckpointToolError, match="unexpectedly large"):
        _load_checkpoint(oversized)


def test_checkpoint_helper_source_never_prints_or_writes_token() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts" / "manage_audit_checkpoint.py").read_text(encoding="utf-8")
    assert "getpass.getpass" in source
    assert "QWR_ANALYST_TOKEN" in source
    assert "The analyst bearer token was not printed" in source
    assert "print(token" not in source
    assert '"Authorization": f"Bearer {token}"' in source
    assert "payload=checkpoint" in source
