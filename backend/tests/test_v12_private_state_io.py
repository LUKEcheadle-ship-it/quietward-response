from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.private_state_io import PrivateStateError, atomic_private_json, load_private_json
from scripts.response_agent_resources import ResourceHandleStore
from scripts.response_agent_v12 import AgentConfig, ResponseAgent


def _config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-private-state",
        key_id="key-private-state",
        secret="private-state-test-secret",
        host_id="host-private-state",
        state_dir=(tmp_path / "state").resolve(),
    )


def _legacy_symlink(path: Path, victim: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(victim)
        return True
    except (OSError, NotImplementedError):
        return False


def test_atomic_private_json_does_not_follow_legacy_predictable_temp_symlink(tmp_path: Path) -> None:
    target = (tmp_path / "state" / "value.json").resolve()
    victim = (tmp_path / "victim.txt").resolve()
    victim.write_text("DO NOT TOUCH", encoding="utf-8")
    legacy = target.with_name(target.name + ".tmp")
    if not _legacy_symlink(legacy, victim):
        pytest.skip("symlink creation unavailable on this host")

    atomic_private_json(target, {"ok": True})

    assert victim.read_text(encoding="utf-8") == "DO NOT TOUCH"
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_load_private_json_rejects_link_like_state(tmp_path: Path) -> None:
    victim = (tmp_path / "real.json").resolve()
    victim.write_text("{}", encoding="utf-8")
    if os.name != "nt":
        victim.chmod(0o600)
    link = (tmp_path / "state.json").resolve()
    if not _legacy_symlink(link, victim):
        pytest.skip("symlink creation unavailable on this host")

    with pytest.raises(PrivateStateError, match="bounded regular file"):
        load_private_json(link, dict)


def test_load_private_json_rejects_non_private_posix_state(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission assertion")
    path = (tmp_path / "state.json").resolve()
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(PrivateStateError, match="group/world"):
        load_private_json(path, dict)


def test_canonical_agent_and_resource_store_ignore_legacy_tmp_symlink(tmp_path: Path) -> None:
    config = _config(tmp_path)
    state_dir = config.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        state_dir.chmod(0o700)
    victim = (tmp_path / "victim.txt").resolve()
    victim.write_text("SAFE", encoding="utf-8")

    demo_legacy = state_dir / "response-agent-demo.json.tmp"
    resource_legacy = state_dir / "response-agent-resource-handles.json.tmp"
    if not (_legacy_symlink(demo_legacy, victim) and _legacy_symlink(resource_legacy, victim)):
        pytest.skip("symlink creation unavailable on this host")

    agent = ResponseAgent(config)
    agent.initialize_demo_fixture()
    ResourceHandleStore(state_dir).issue(
        kind="test",
        identity={"id": 1},
        fingerprint="private-state-fingerprint",
        display={},
    )

    assert victim.read_text(encoding="utf-8") == "SAFE"
    assert agent.demo_state_path.is_file()
    assert (state_dir / "response-agent-resource-handles.json").is_file()
