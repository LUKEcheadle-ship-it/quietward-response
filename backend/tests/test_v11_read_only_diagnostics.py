from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

from app.services.action_registry import ACTION_REGISTRY
from app.services.recommendation import recommendations_for


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from response_agent import AgentConfig, ResponseAgent
from response_agent_diagnostics import collect_host_diagnostic


DIAGNOSTIC_ACTIONS = {
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
}


def _event(event_type: str, category: str):
    return SimpleNamespace(event_type=event_type, category=category)


def test_registry_contains_only_demo_mutation_and_read_only_diagnostics() -> None:
    assert set(ACTION_REGISTRY) == {
        "restart_quietward_demo_service",
        *DIAGNOSTIC_ACTIONS,
    }
    for action_type in DIAGNOSTIC_ACTIONS:
        definition = ACTION_REGISTRY[action_type]
        assert definition.risk_level == "low"
        assert definition.approval_required is True
        assert definition.reversible is True
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({"pid": 1})

    forbidden = {
        "terminate_process_by_handle",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
        "stop_process",
        "block_network",
        "isolate_host",
    }
    assert not (forbidden & set(ACTION_REGISTRY))


def test_recommendations_bind_diagnostics_to_relevant_incidents() -> None:
    network = recommendations_for([_event("c2_beacon_detected", "network")])
    network_types = {
        item.get("registry_action_type")
        for item in network
        if item.get("registry_action_type")
    }
    assert {
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "collect_network_diagnostic",
    } <= network_types

    persistence = recommendations_for([_event("persistence_change", "persistence")])
    persistence_types = {
        item.get("registry_action_type")
        for item in persistence
        if item.get("registry_action_type")
    }
    assert "collect_host_diagnostic" in persistence_types
    assert "collect_process_diagnostic" in persistence_types
    assert "collect_network_diagnostic" not in persistence_types


def test_response_agent_capabilities_are_narrow(tmp_path: Path) -> None:
    agent = ResponseAgent(
        AgentConfig(
            base_url="http://127.0.0.1:8002",
            agent_id="agent-1",
            key_id="key-1",
            secret="s" * 32,
            host_id="host-1",
            state_dir=tmp_path.resolve(),
        )
    )
    capabilities = agent.capabilities()
    assert set(capabilities["read_only_actions"]) == DIAGNOSTIC_ACTIONS
    assert capabilities["mutating_actions"] == ["restart_quietward_demo_service"]
    assert capabilities["arbitrary_command_execution"] is False
    assert capabilities["raw_process_command_lines"] is False
    assert capabilities["raw_executable_paths"] is False
    assert capabilities["raw_remote_network_addresses"] is False


def test_host_diagnostic_is_bounded_and_read_only(tmp_path: Path) -> None:
    result = collect_host_diagnostic(tmp_path.resolve())
    assert result["read_only"] is True
    assert result["system_state_changed"] is False
    assert set(result["agent_state_disk"]) == {"total", "used", "free"}


def test_agent_source_has_no_generic_command_execution_or_destructive_surface() -> None:
    agent_source = (SCRIPTS / "response_agent.py").read_text(encoding="utf-8").lower()
    diagnostics_source = (SCRIPTS / "response_agent_diagnostics.py").read_text(encoding="utf-8").lower()
    combined = agent_source + "\n" + diagnostics_source

    for forbidden in (
        "import subprocess",
        "from subprocess",
        "os.system(",
        "shell=true",
        "terminate_process_by_handle",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
    ):
        assert forbidden not in combined
