from __future__ import annotations

from pathlib import Path

from scripts import response_agent as base
from scripts import response_agent_v12 as v12


def _config(tmp_path: Path) -> base.AgentConfig:
    return base.AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-network-test",
        key_id="key-network-test",
        secret="network-test-secret",
        host_id="host-network-test",
        state_dir=tmp_path.resolve(),
    )


def test_v12_agent_registers_network_action_as_parameter_free() -> None:
    # Importing the official v1.2 agent extends only the finite parameter-mode
    # table; it does not add a generic executor or mutating-action classification.
    assert base._ACTION_PARAMETER_MODE["collect_network_diagnostic"] == "none"
    assert "collect_network_diagnostic" not in base._MUTATING_ACTIONS
    assert "collect_network_diagnostic" not in base._HANDLE_ACTIONS


def test_linux_v12_agent_advertises_network_diagnostic(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(v12.platform, "system", lambda: "Linux")
    agent = v12.ResponseAgent(_config(tmp_path))
    capabilities = agent.capabilities()
    assert "collect_network_diagnostic" in capabilities["read_only_actions"]
    assert capabilities["arbitrary_command_execution"] is False


def test_non_linux_v12_agent_does_not_advertise_network_diagnostic(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(v12.platform, "system", lambda: "Windows")
    agent = v12.ResponseAgent(_config(tmp_path))
    assert "collect_network_diagnostic" not in agent.capabilities()["read_only_actions"]


def test_network_action_routes_only_to_read_only_network_collector(tmp_path: Path, monkeypatch) -> None:
    agent = v12.ResponseAgent(_config(tmp_path))
    expected = {
        "read_only": True,
        "system_state_changed": False,
        "connections": [],
        "raw_network_addresses_returned": False,
    }
    called = {"count": 0}

    def fake_collect(store):
        assert store is agent.resources
        called["count"] += 1
        return dict(expected)

    monkeypatch.setattr(v12, "collect_network_diagnostic", fake_collect)
    result = agent._execute_action(
        {"action_type": "collect_network_diagnostic", "parameters": {}},
        recover_after_started=False,
    )
    assert result == expected
    assert called["count"] == 1
