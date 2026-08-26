from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.quietward_adapter_credentials import (
    AdapterCredential,
    derive_event_ingestion_subkey_from_secret,
    provision_from_agent_config,
)


def _write_agent_config(path: Path, *, endpoint_secret: str = "endpoint-secret-that-must-not-be-copied") -> None:
    path.write_text(
        json.dumps(
            {
                "base_url": "http://127.0.0.1:8002",
                "agent_id": "agent-alpha",
                "key_id": "key-alpha",
                "secret": endpoint_secret,
                "host_id": "host-alpha",
                "state_dir": str((path.parent / "state").resolve()),
                "timeout_seconds": 5.0,
            }
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        path.chmod(0o600)


def test_adapter_config_contains_only_derived_event_credential(tmp_path: Path) -> None:
    agent = (tmp_path / "agent.json").resolve()
    adapter = (tmp_path / "adapter.json").resolve()
    endpoint_secret = "endpoint-secret-that-must-not-be-copied"
    _write_agent_config(agent, endpoint_secret=endpoint_secret)

    provision_from_agent_config(agent, adapter)
    raw = json.loads(adapter.read_text(encoding="utf-8"))
    assert raw["credential_scope"] == "quietward_event_ingestion_only"
    assert "secret" not in raw
    assert endpoint_secret not in adapter.read_text(encoding="utf-8")
    loaded = AdapterCredential.from_file(adapter)
    assert loaded.event_subkey == derive_event_ingestion_subkey_from_secret(endpoint_secret)
    if os.name != "nt":
        assert adapter.stat().st_mode & 0o077 == 0


def test_adapter_provisioning_does_not_follow_predictable_temp_symlink(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink regression fixture is POSIX-only")

    agent = (tmp_path / "agent.json").resolve()
    adapter = (tmp_path / "adapter.json").resolve()
    victim = (tmp_path / "victim.txt").resolve()
    legacy_temporary = adapter.with_name(adapter.name + ".tmp")
    _write_agent_config(agent)
    victim.write_text("do-not-touch", encoding="utf-8")
    legacy_temporary.symlink_to(victim)

    provision_from_agent_config(agent, adapter)

    assert victim.read_text(encoding="utf-8") == "do-not-touch"
    assert legacy_temporary.is_symlink()
    assert adapter.is_file()
    assert not adapter.is_symlink()


def test_different_endpoint_secrets_produce_different_adapter_subkeys() -> None:
    assert derive_event_ingestion_subkey_from_secret("endpoint-one") != derive_event_ingestion_subkey_from_secret("endpoint-two")
