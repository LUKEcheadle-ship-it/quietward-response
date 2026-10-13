from __future__ import annotations

import copy
import re
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

from incident_triage_bundle import collect_incident_triage_bundle
from ingest_quietward_handoff import HandoffError, _validate_event
from response_agent import AgentConfig, ResponseAgent
from response_agent_diagnostics import collect_host_diagnostic


DIAGNOSTIC_ACTIONS = {
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
    "collect_incident_triage_bundle",
}
MUTATING_ACTIONS = {
    "restart_quietward_demo_service",
    "terminate_evidence_process",
}
PROCESS_HANDLE = re.compile(r"^qwrp-[0-9a-f]{32}$")


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
            "quietward_finding_hmac_sha256": "f" * 32,
            "quietward_score": 91.0,
            "quietward_mode": "observe",
            "requires_human_approval": True,
            "observation_only_source": True,
            "executable_authority": False,
            "investigation_hints": ["host_health", "process_inventory", "network_snapshot"],
            "operating_system": "Linux",
            "quietward_source_cycle_id": None,
            "quietward_source_chain_hash": None,
        },
    }


def _guided_handoff_event(host_id: str = "host-1") -> dict:
    payload = _handoff_event(host_id)
    payload["metadata"].update(
        {
            "quietward_response_context_version": "1.1",
            "response_priority": "urgent",
            "evidence_strength": "strong",
            "recommended_playbook": "network_triage",
        }
    )
    return payload


def _agent_config(tmp_path: Path, host_id: str = "host-1") -> AgentConfig:
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-1",
        key_id="key-1",
        secret="s" * 32,
        host_id=host_id,
        state_dir=tmp_path.resolve(),
    )


def test_registry_contains_only_explicit_diagnostics_and_mutations() -> None:
    assert set(ACTION_REGISTRY) == DIAGNOSTIC_ACTIONS | MUTATING_ACTIONS
    for action_type in DIAGNOSTIC_ACTIONS:
        definition = ACTION_REGISTRY[action_type]
        assert definition.risk_level == "low"
        assert definition.approval_required is True
        assert definition.reversible is True
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({"pid": 1})

    containment = ACTION_REGISTRY["terminate_evidence_process"]
    assert containment.risk_level == "high"
    assert containment.approval_required is True
    assert containment.reversible is False
    assert containment.validate_parameters({})
    assert containment.validate_parameters({"pid": 1234})
    assert containment.validate_parameters({"evidence_handle": "qwrp-" + "a" * 32}) == []

    forbidden = {
        "run_shell",
        "run_arbitrary_command",
        "terminate_arbitrary_process",
        "quarantine_arbitrary_path",
        "block_arbitrary_address",
        "isolate_host",
    }
    assert not (forbidden & set(ACTION_REGISTRY))


def test_recommendations_bind_diagnostics_and_process_containment_to_relevant_incidents() -> None:
    malware = recommendations_for([_event("malware_process_detected", "malware")])
    malware_types = {
        item.get("registry_action_type")
        for item in malware
        if item.get("registry_action_type")
    }
    assert {
        "collect_host_diagnostic",
        "collect_process_diagnostic",
        "terminate_evidence_process",
    } <= malware_types

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
    assert "terminate_evidence_process" in persistence_types
    assert "collect_network_diagnostic" not in persistence_types


def test_response_agent_capabilities_are_narrow_and_evidence_bound(tmp_path: Path) -> None:
    agent = ResponseAgent(_agent_config(tmp_path))
    capabilities = agent.capabilities()
    assert set(capabilities["read_only_actions"]) == DIAGNOSTIC_ACTIONS
    assert set(capabilities["mutating_actions"]) == MUTATING_ACTIONS
    assert capabilities["arbitrary_command_execution"] is False
    assert capabilities["arbitrary_process_targeting"] is False
    assert capabilities["evidence_bound_process_containment"] is True
    assert capabilities["raw_process_command_lines"] is False
    assert capabilities["raw_executable_paths"] is False
    assert capabilities["raw_remote_network_addresses"] is False


def test_host_diagnostic_is_bounded_and_read_only(tmp_path: Path) -> None:
    result = collect_host_diagnostic(tmp_path.resolve())
    assert result["read_only"] is True
    assert result["system_state_changed"] is False
    assert set(result["agent_state_disk"]) == {"total", "used", "free"}


def test_incident_triage_bundle_is_bounded_read_only_and_mints_only_opaque_handles(tmp_path: Path) -> None:
    result = collect_incident_triage_bundle(tmp_path.resolve(), b"n" * 32)
    assert result["read_only"] is True
    assert result["system_state_changed"] is False
    assert result["arbitrary_command_execution"] is False
    assert result["raw_process_command_lines"] is False
    assert result["raw_executable_paths"] is False
    assert result["raw_remote_network_addresses"] is False
    assert result["evidence_handles_local_only"] is True
    assert "host" in result["components"]
    assert result["component_count"] >= 1
    process = result["components"].get("process")
    if isinstance(process, dict):
        assert process["evidence_handle_scheme"] == "endpoint_local_hmac_v1"
        assert process["raw_process_target_parameters_required"] is False
        for row in process.get("processes", []):
            if "evidence_handle" in row:
                assert PROCESS_HANDLE.fullmatch(row["evidence_handle"])


def test_quietward_handoff_payload_matches_response_event_schema_and_legacy_optional_handle(tmp_path: Path) -> None:
    payload = _handoff_event()
    validated = EventCreate.model_validate(payload)
    assert validated.source == "quietward"
    assert validated.metadata["operating_system"] == "Linux"
    assert "resolution_target_handle" not in payload["evidence"]
    assert _validate_event(payload, _agent_config(tmp_path)) == payload


def test_handoff_importer_accepts_valid_optional_resolution_target_handle(tmp_path: Path) -> None:
    payload = _handoff_event()
    payload["evidence"]["resolution_target_handle"] = "qwrt-" + "c" * 32
    assert _validate_event(payload, _agent_config(tmp_path)) == payload


def test_handoff_importer_rejects_malformed_optional_resolution_target_handle(tmp_path: Path) -> None:
    payload = _handoff_event()
    payload["evidence"]["resolution_target_handle"] = "C:\\sensitive\\payload.exe"
    with pytest.raises(HandoffError, match="resolution target handle"):
        _validate_event(payload, _agent_config(tmp_path))


def test_handoff_importer_accepts_guided_context_v11(tmp_path: Path) -> None:
    payload = _guided_handoff_event()
    validated = EventCreate.model_validate(payload)
    assert validated.metadata["response_priority"] == "urgent"
    assert validated.metadata["recommended_playbook"] == "network_triage"
    assert _validate_event(payload, _agent_config(tmp_path)) == payload


def test_handoff_importer_rejects_unknown_guided_playbook(tmp_path: Path) -> None:
    payload = _guided_handoff_event()
    payload["metadata"]["recommended_playbook"] = "run_anything"
    with pytest.raises(HandoffError, match="recommended playbook"):
        _validate_event(payload, _agent_config(tmp_path))


def test_handoff_importer_accepts_valid_evidence_chain_provenance(tmp_path: Path) -> None:
    payload = _handoff_event()
    payload["metadata"]["quietward_source_cycle_id"] = 17
    payload["metadata"]["quietward_source_chain_hash"] = "b" * 64
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


def test_handoff_importer_rejects_nested_data_smuggling_and_summary_tampering(
    tmp_path: Path,
) -> None:
    config = _agent_config(tmp_path)
    hidden_subject = copy.deepcopy(_handoff_event())
    hidden_subject["metadata"]["raw_subject"] = "/private/secret/path"
    with pytest.raises(HandoffError, match="metadata contains unexpected fields"):
        _validate_event(hidden_subject, config)

    hidden_address = copy.deepcopy(_handoff_event())
    hidden_address["evidence"]["remote_address"] = "203.0.113.5"
    with pytest.raises(HandoffError, match="evidence contains unexpected"):
        _validate_event(hidden_address, config)

    tampered_summary = copy.deepcopy(_handoff_event())
    tampered_summary["summary"] = "Raw sensitive detail was inserted here."
    with pytest.raises(HandoffError, match="sanitized canonical form"):
        _validate_event(tampered_summary, config)


def test_handoff_importer_requires_privacy_keyed_finding_identity(tmp_path: Path) -> None:
    config = _agent_config(tmp_path)
    raw_id = copy.deepcopy(_handoff_event())
    raw_id["metadata"]["quietward_finding_hmac_sha256"] = "qwf-internal-id"
    with pytest.raises(HandoffError, match="finding identity is not privacy-keyed"):
        _validate_event(raw_id, config)


def test_handoff_importer_rejects_partial_or_invalid_provenance(tmp_path: Path) -> None:
    config = _agent_config(tmp_path)
    partial = copy.deepcopy(_handoff_event())
    partial["metadata"]["quietward_source_cycle_id"] = 4
    with pytest.raises(HandoffError, match="evidence-chain hash"):
        _validate_event(partial, config)

    invalid = copy.deepcopy(_handoff_event())
    invalid["metadata"]["quietward_source_cycle_id"] = 0
    invalid["metadata"]["quietward_source_chain_hash"] = "c" * 64
    with pytest.raises(HandoffError, match="source cycle"):
        _validate_event(invalid, config)


def test_agent_source_has_no_generic_command_or_arbitrary_target_surface() -> None:
    paths = [
        SCRIPTS / "response_agent.py",
        SCRIPTS / "response_agent_diagnostics.py",
        SCRIPTS / "incident_triage_bundle.py",
        SCRIPTS / "evidence_store.py",
        SCRIPTS / "process_containment.py",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    for forbidden in (
        "import subprocess",
        "from subprocess",
        "os.system(",
        "shell=true",
        "run_arbitrary_command",
        "arbitrary_pid_accepted\": true",
        "quarantine_arbitrary_path",
        "block_arbitrary_address",
    ):
        assert forbidden not in combined
