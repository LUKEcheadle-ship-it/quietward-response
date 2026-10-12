"""Private state writes use disposable files, never real endpoint credentials."""
from __future__ import annotations

import importlib
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
agent = importlib.import_module("response_agent")
enrollment = importlib.import_module("enroll_response_agent")


@pytest.fixture(params=["state", "enrollment"])
def writer(request):
    if request.param == "state":
        return agent, lambda p, v: agent._atomic_json(p, v)
    return enrollment, lambda p, v: enrollment._private_json(p, v, force=True)


def test_exact_binary_json_and_private_posix_mode(writer, tmp_path):
    _, write = writer
    target = tmp_path / "private.json"
    value = {"synthetic": "line one\nline two", "unicode": "café", "count": 3}
    write(target, value)
    assert target.read_bytes() == (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == [target.name]


def test_predictable_temp_file_is_never_touched(writer, tmp_path):
    _, write = writer
    target = tmp_path / "private.json"
    old_temp = target.with_name(target.name + ".tmp")
    old_temp.write_bytes(b"preserve unrelated bytes")
    write(target, {"synthetic": True})
    assert old_temp.read_bytes() == b"preserve unrelated bytes"
    assert json.loads(target.read_bytes()) == {"synthetic": True}


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink test; not a Windows reparse claim")
def test_predictable_temp_symlink_does_not_truncate_its_target(writer, tmp_path):
    _, write = writer
    target = tmp_path / "private.json"
    other = tmp_path / "unrelated.txt"
    other.write_bytes(b"PRESERVE")
    target.with_name(target.name + ".tmp").symlink_to(other)
    write(target, {"synthetic": True})
    assert other.read_bytes() == b"PRESERVE"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink test; not a Windows reparse claim")
def test_destination_symlink_is_rejected(writer, tmp_path):
    _, write = writer
    target = tmp_path / "private.json"
    other = tmp_path / "unrelated.txt"
    other.write_bytes(b"PRESERVE")
    target.symlink_to(other)
    with pytest.raises((ValueError, OSError), match="symlink"):
        write(target, {"synthetic": True})
    assert target.is_symlink() and other.read_bytes() == b"PRESERVE"


def test_replace_failure_preserves_old_state_and_cleans_private_temp(writer, tmp_path):
    module, write = writer
    target = tmp_path / "private.json"
    target.write_bytes(b"OLD STATE")
    with patch.object(module.os, "replace", side_effect=OSError("injected replace failure")):
        with pytest.raises(OSError, match="replace failure"):
            write(target, {"synthetic": True})
    assert target.read_bytes() == b"OLD STATE"
    assert list(tmp_path.iterdir()) == [target]


def test_fsync_failure_preserves_old_state_and_cleans_private_temp(writer, tmp_path):
    module, write = writer
    target = tmp_path / "private.json"
    target.write_bytes(b"OLD STATE")
    with patch.object(module.os, "fsync", side_effect=OSError("injected fsync failure")):
        with pytest.raises(OSError, match="fsync failure"):
            write(target, {"synthetic": True})
    assert target.read_bytes() == b"OLD STATE"
    assert list(tmp_path.iterdir()) == [target]


def test_enrollment_without_force_creates_config(tmp_path):
    target = tmp_path / "agent.json"
    enrollment._private_json(target, {"synthetic": True}, force=False)
    assert json.loads(target.read_bytes()) == {"synthetic": True}
    assert list(tmp_path.iterdir()) == [target]


def test_enrollment_without_force_preserves_existing_config(tmp_path):
    target = tmp_path / "agent.json"
    target.write_bytes(b"EXISTING")
    with pytest.raises(ValueError, match="already exists"):
        enrollment._private_json(target, {"synthetic": True}, force=False)
    assert target.read_bytes() == b"EXISTING"


def test_concurrent_enrollment_cannot_overwrite_winner(tmp_path):
    target = tmp_path / "agent.json"
    native_link = os.link
    def competing_enrollment(source, destination):
        Path(destination).write_bytes(b"OTHER ENROLLMENT")
        return native_link(source, destination)
    with patch.object(enrollment.os, "link", side_effect=competing_enrollment):
        with pytest.raises(ValueError, match="already exists"):
            enrollment._private_json(target, {"synthetic": True}, force=False)
    assert target.read_bytes() == b"OTHER ENROLLMENT"
    assert list(tmp_path.iterdir()) == [target]


def test_unsupported_atomic_no_replace_fails_closed(tmp_path):
    target = tmp_path / "agent.json"
    with patch.object(enrollment.os, "link", side_effect=OSError("no hard links")):
        with pytest.raises(OSError, match="no hard links"):
            enrollment._private_json(target, {"synthetic": True}, force=False)
    assert not list(tmp_path.iterdir())


def test_relative_config_path_is_refused():
    with pytest.raises(ValueError, match="absolute"):
        enrollment._private_json(Path("relative.json"), {"synthetic": True}, force=False)
