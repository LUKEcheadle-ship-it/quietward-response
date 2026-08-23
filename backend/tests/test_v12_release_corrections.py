from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts import response_agent_v12 as v12
from scripts.response_agent import write_agent_config
from scripts.response_agent_file_v12 import collect_file_diagnostic
from scripts.response_agent_resources import ResourceHandleStore


def _config(tmp_path: Path, *, process: bool = False, files: bool = False) -> v12.AgentConfig:
    managed = (tmp_path / "managed",) if files else ()
    for root in managed:
        root.mkdir(parents=True, exist_ok=True)
    return v12.AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-release-test",
        key_id="key-release-test",
        secret="s" * 48,
        host_id="host-release-test",
        state_dir=(tmp_path / "state").resolve(),
        managed_roots=managed,
        enable_process_termination=process,
        enable_file_quarantine=files,
    )


def test_runtime_config_loader_rejects_public_posix_permissions(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode check")
    path = tmp_path / "agent.json"
    write_agent_config(path, _config(tmp_path))
    path.chmod(0o644)
    with pytest.raises(v12.ResponseAgentError, match="group/world"):
        v12.AgentConfig.from_file(path)


def test_runtime_config_loader_rejects_symlink(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink unavailable")
    real = tmp_path / "real-agent.json"
    write_agent_config(real, _config(tmp_path))
    link = tmp_path / "agent-link.json"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(v12.ResponseAgentError, match="symbolic link"):
        v12.AgentConfig.from_file(link)


def test_linux_process_termination_is_not_advertised_without_pidfd(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(v12.platform, "system", lambda: "Linux")
    monkeypatch.delattr(v12.os, "pidfd_open", raising=False)
    monkeypatch.delattr(v12.signal, "pidfd_send_signal", raising=False)
    agent = v12.ResponseAgent(_config(tmp_path, process=True))
    capabilities = agent.capabilities()
    assert capabilities["mutating_actions"]["terminate_process_by_handle"] is False
    assert capabilities["safe_process_termination_supported"] is False


def test_file_diagnostic_has_total_byte_budget(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "a.bin").write_bytes(b"a" * 60)
    (managed / "b.bin").write_bytes(b"b" * 60)
    store = ResourceHandleStore(tmp_path / "state")

    result = collect_file_diagnostic(store, (managed,), byte_budget=100)
    assert result["scan_byte_budget"] == 100
    assert result["scanned_bytes"] == 60
    assert len(result["files"]) == 1
    assert result["skipped_due_to_byte_budget"] == 1
    assert result["truncated"] is True


def test_release_contains_continuous_agent_and_least_privilege_adapter_installers() -> None:
    root = Path(__file__).resolve().parents[2]
    poller = (root / "scripts" / "poll_response_agent.py").read_text(encoding="utf-8")
    linux = (root / "scripts" / "install_response_agent_user_service.sh").read_text(encoding="utf-8")
    windows = (root / "scripts" / "install_response_agent_windows.ps1").read_text(encoding="utf-8")
    adapter_linux = (root / "scripts" / "install_quietward_adapter_user_service.sh").read_text(encoding="utf-8")
    adapter_windows = (root / "scripts" / "install_quietward_adapter_windows.ps1").read_text(encoding="utf-8")
    adapter_runtime = (root / "scripts" / "forward_quietward_events.py").read_text(encoding="utf-8")

    assert "while not stop.is_set()" in poller
    assert '"--once"' in poller
    assert "quietward-response-agent.service" in linux
    assert "response_agent_file_v12.py" in linux
    assert "RunLevel Limited" in windows
    assert "forward_quietward_events.py" in adapter_linux
    assert "provision_quietward_adapter.py" in adapter_linux
    assert "adapter.json" in adapter_linux
    assert "forward_quietward_events.py" in adapter_windows
    assert "provision_quietward_adapter.py" in adapter_windows
    assert "adapter.json" in adapter_windows
    assert "RunLevel Limited" in adapter_windows
    assert "ReloadingEventOnlyClient" in adapter_runtime
    assert "quietward_event_ingestion_only" in adapter_runtime


def test_health_reports_real_v12_scope(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    value = response.json()
    assert value["controlled_action_count"] == 8
    assert value["response_scope"] == "typed_controlled_response_v12"
    assert value["generic_command_execution"] is False
