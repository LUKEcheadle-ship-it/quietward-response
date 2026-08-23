from __future__ import annotations

from types import SimpleNamespace

from app.services.correlation_v12 import correlation_reasons
from app.services.recommendation_v12 import recommendations_for


def _event(
    event_type: str,
    category: str,
    severity: str,
    *,
    normalized=None,
):
    return SimpleNamespace(
        event_type=event_type,
        category=category,
        severity=severity,
        normalized=normalized or {},
        payload=normalized or {},
    )


def _registry_actions(events) -> set[str]:
    return {
        str(item["registry_action_type"])
        for item in recommendations_for(list(events))
        if item.get("registry_action_type")
    }


def test_plain_process_start_does_not_enable_termination() -> None:
    actions = _registry_actions(
        [_event("process_start", "execution", "high", normalized={"process": {"command_name": "python"}})]
    )
    assert "collect_process_diagnostic" in actions
    assert "terminate_process_by_handle" not in actions


def test_high_signal_high_process_can_enable_termination() -> None:
    actions = _registry_actions(
        [
            _event(
                "process_start",
                "execution",
                "high",
                normalized={
                    "process": {
                        "command_name": "powershell.exe",
                        "suspicious_markers": ["reverse_shell"],
                    }
                },
            )
        ]
    )
    assert "terminate_process_by_handle" in actions


def test_generic_file_change_does_not_enable_quarantine() -> None:
    actions = _registry_actions(
        [_event("file_change", "file", "high", normalized={"file": {"subject": "config"}})]
    )
    assert "collect_file_diagnostic" in actions
    assert "quarantine_artifact_by_handle" not in actions
    assert "restore_quarantined_artifact_by_handle" not in actions


def test_malware_signature_enables_handle_quarantine() -> None:
    actions = _registry_actions([_event("malware_signature", "malware", "high")])
    assert "collect_file_diagnostic" in actions
    assert "quarantine_artifact_by_handle" in actions
    assert "restore_quarantined_artifact_by_handle" in actions


def test_same_category_without_shared_indicator_is_not_a_correlation_reason() -> None:
    first = _event(
        "outbound_connection",
        "network",
        "high",
        normalized={"network": {"destination_hash": "destination-a"}},
    )
    second = _event(
        "outbound_connection",
        "network",
        "high",
        normalized={"network": {"destination_hash": "destination-b"}},
    )
    reasons = correlation_reasons(second, first)
    assert reasons == ["same host within the configured correlation window"]


def test_high_signal_execution_to_network_is_a_compatible_attack_stage() -> None:
    execution = _event(
        "process_start",
        "execution",
        "high",
        normalized={
            "process": {
                "command_name": "powershell.exe",
                "suspicious_markers": ["reverse_shell"],
            }
        },
    )
    network = _event(
        "outbound_connection",
        "network",
        "high",
        normalized={"network": {"destination_hash": "destination-a"}},
    )
    reasons = correlation_reasons(network, execution)
    assert any("compatible high-signal attack stages" in item for item in reasons)


def test_api_keeps_unrelated_same_category_events_in_separate_incidents(client, event_factory) -> None:
    first = client.post(
        "/api/v1/events",
        json=event_factory(
            index=1,
            host_id="quality-host",
            event_type="outbound_connection",
            category="network",
            severity="high",
            network={"destination_hash": "destination-a", "destination_port": 443},
        ),
    )
    second = client.post(
        "/api/v1/events",
        json=event_factory(
            index=2,
            host_id="quality-host",
            event_type="outbound_connection",
            category="network",
            severity="high",
            network={"destination_hash": "destination-b", "destination_port": 443},
        ),
    )
    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    assert first.json()["incident_id"] != second.json()["incident_id"]


def test_api_joins_high_signal_execution_and_network_stages(client, event_factory) -> None:
    execution = client.post(
        "/api/v1/events",
        json=event_factory(
            index=10,
            host_id="attack-chain-host",
            event_type="process_start",
            category="execution",
            severity="high",
            process={
                "command_name": "powershell.exe",
                "suspicious_markers": ["reverse_shell"],
            },
        ),
    )
    network = client.post(
        "/api/v1/events",
        json=event_factory(
            index=11,
            host_id="attack-chain-host",
            event_type="outbound_connection",
            category="network",
            severity="high",
            network={"destination_hash": "destination-c", "destination_port": 443},
        ),
    )
    assert execution.status_code == 201, execution.text
    assert network.status_code == 201, network.text
    assert execution.json()["incident_id"] == network.json()["incident_id"]
