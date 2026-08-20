from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.action_registry import ACTION_REGISTRY
from app.services.recommendation import recommendations_for


DIAGNOSTIC_ACTIONS = {
    "collect_process_diagnostic",
    "collect_network_diagnostic",
    "collect_persistence_diagnostic",
    "collect_file_diagnostic",
    "collect_container_diagnostic",
    "collect_identity_diagnostic",
    "collect_vulnerability_diagnostic",
    "collect_integrity_diagnostic",
}


def _event(event_type: str, category: str) -> SimpleNamespace:
    return SimpleNamespace(event_type=event_type, category=category)


def test_expanded_registry_stays_typed_parameter_free_and_approval_gated() -> None:
    assert set(ACTION_REGISTRY) == {
        "restart_quietward_demo_service",
        *DIAGNOSTIC_ACTIONS,
    }
    for action_type in DIAGNOSTIC_ACTIONS:
        definition = ACTION_REGISTRY[action_type]
        assert definition.approval_required is True
        assert definition.reversible is True
        assert definition.risk_level == "low"
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({"command": "whoami"}) == [
            "this action accepts no parameters"
        ]


@pytest.mark.parametrize(
    ("event_type", "category", "expected_action"),
    [
        ("process_start", "execution", "collect_process_diagnostic"),
        ("privilege_escalation", "privilege", "collect_process_diagnostic"),
        ("malware_signature", "malware", "collect_file_diagnostic"),
        ("yara_match", "malware", "collect_file_diagnostic"),
        ("persistence_change", "persistence", "collect_persistence_diagnostic"),
        ("new_listening_port", "network", "collect_network_diagnostic"),
        ("outbound_connection", "network", "collect_network_diagnostic"),
        ("container_escape_indicator", "container", "collect_container_diagnostic"),
        ("container_configuration_change", "container", "collect_container_diagnostic"),
        ("auth_failure", "identity", "collect_identity_diagnostic"),
        ("account_change", "identity", "collect_identity_diagnostic"),
        ("package_vulnerability", "vulnerability", "collect_vulnerability_diagnostic"),
        ("configuration_weakness", "configuration", "collect_vulnerability_diagnostic"),
        ("self_integrity_change", "integrity", "collect_integrity_diagnostic"),
        ("evidence_integrity_failure", "integrity", "collect_integrity_diagnostic"),
    ],
)
def test_detected_attack_classes_enable_matching_controlled_diagnostics(
    event_type: str,
    category: str,
    expected_action: str,
) -> None:
    recommendations = recommendations_for([_event(event_type, category)])
    enabled = {
        item.get("registry_action_type")
        for item in recommendations
        if item.get("enabled") is True
    }
    assert expected_action in enabled


def test_expansion_never_recommends_generic_command_execution() -> None:
    recommendations = recommendations_for(
        [
            _event("malware_signature", "malware"),
            _event("container_escape_indicator", "container"),
            _event("privilege_escalation", "privilege"),
        ]
    )
    registry_actions = {
        str(item.get("registry_action_type"))
        for item in recommendations
        if item.get("registry_action_type")
    }
    assert registry_actions <= set(ACTION_REGISTRY)
    assert not any("command" in action_type or "shell" in action_type for action_type in registry_actions)
