from __future__ import annotations

import copy
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.schemas.event import EventCreate
from app.services.action_registry import ACTION_REGISTRY
from app.services.recommendation import recommendations_for


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ingest_quietward_handoff import HandoffError, _validate_event
from response_agent import AgentConfig, ResponseAgent
from response_agent_diagnostics import collect_host_diagnostic


DIAGNOSTIC_ACTIONS = {
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
}


def _event(event_type: str, category: str):
    return SimpleNamespace(event_type=event_type, category=category)


def _handoff_event(host_id: str = "host-1") -> dict:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "quietward",
        "source_version": "0.6.0-alpha.1",
        "host_id": host_id,
        "host_name": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "quietward_network_finding",
        "category": "network",
        "severity": "high",
        "confidence": 0.91,
        "summary": "QuietWard correlated 3 evidence item(s) into a high network finding.",
        "evidence": {
            "event_count": 3,
            "event_kinds": ["outbound_connection"],
            "correlation_signal_codes": ["process_network_corroboration"],
            "subject_hmac_sha256": "a" * 32,
            "subject_type": "network",
        },
        "process": None,
        "file": None,
        "network": None,
        "persistence": None,
        "metadata": {
            "quietward_response_context_version": "1.0",
            "quietward_finding_id": "qwf-example",
            "quietward_score": 91.0,
            "quietward_mode": "observe",
            "requires_human_approval": True,
            "observation_only_source": True,
            "executable_authority": False,
            "investigation_hints": ["host_health", "process_inventory", "network_snapshot"],
            "operating_system": "Linux",
        },
    }


def _agent_config(tmp_path: Path, host_id: str = "host-1") -> AgentConfig:
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-1",
        key_id="key-1",
        secret="s" * 32,
        host_id=host_id,
        state_dir=tmp_path.resolve(),
    )


def test_registry_contains_only_demo_mutation_and_read_only_diagnostics() -> None:
    assert set(ACTION_REGISTRY) == {"restart_quietward_demo_service"} | DIAGNOSTIC_ACTIONS
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
    agent = ResponseAgent(_agent_config(tmp_path))
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


def test_quietward_handoff_payload_matches_response_event_schema(tmp_path: Path) -> None:
    payload = _handoff_event()
    validated = EventCreate.model_validate(payload)
    assert validated.source == "quietward"
    assert validated.metadata["operating_system"] == "Linux"
    assert _validate_event(payload, _agent_config(tmp_path)) == payload


def test_handoff_importer_rejects_raw_context_or_executable_authority(tmp_path: Path) -> None:
    config = _agent_config(tmp_path)
    raw_network = copy.deepcopy(_handoff_event())
    raw_network["network"] = {"remote_address": "203.0.113.5"}
    with pytest.raises(HandoffError, match="raw network context"):
        _validate_event(raw_network, config)

    executable = copy.deepcopy(_handoff_event())
    executable["metadata"]["executable_authority"] = True
    with pytest.raises(HandoffError, match="executable authority"):
        _validate_event(executable, config)


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
