from __future__ import annotations

from types import SimpleNamespace

from app.services.guided_response import quietward_guidance
from app.services.recommendation import probable_cause_for, recommendations_for


def _event(*, executable_authority: bool = False):
    return SimpleNamespace(
        source="quietward",
        category="network",
        event_type="quietward_network_finding",
        payload={
            "metadata": {
                "quietward_response_context_version": "1.1",
                "observation_only_source": True,
                "executable_authority": executable_authority,
                "response_priority": "urgent",
                "evidence_strength": "strong",
                "recommended_playbook": "network_triage",
                "investigation_hints": [
                    "host_health",
                    "process_inventory",
                    "network_snapshot",
                    "not-an-allowed-hint",
                ],
            }
        },
    )


def test_quietward_guidance_accepts_only_sanitized_allowlisted_context() -> None:
    guidance = quietward_guidance([_event()])

    assert guidance is not None
    assert guidance["priority"] == "urgent"
    assert guidance["evidence_strength"] == "strong"
    assert guidance["recommended_playbook"] == "network_triage"
    assert guidance["investigation_hints"] == [
        "host_health",
        "network_snapshot",
        "process_inventory",
    ]
    assert guidance["executable_authority"] is False


def test_quietward_guidance_fails_closed_on_executable_authority_claim() -> None:
    assert quietward_guidance([_event(executable_authority=True)]) is None


def test_guided_network_profile_drives_bounded_response_recommendations() -> None:
    event = _event()
    actions = recommendations_for([event])
    titles = {str(action["title"]) for action in actions}
    registry_actions = {
        str(action["registry_action_type"])
        for action in actions
        if action.get("registry_action_type")
    }

    assert "Collect guided incident triage bundle" in titles
    assert "collect_incident_triage_bundle" in registry_actions
    assert "collect_host_diagnostic" in registry_actions
    assert "collect_process_diagnostic" in registry_actions
    assert "collect_network_diagnostic" in registry_actions

    cause = probable_cause_for([event])
    assert "urgent priority" in cause
    assert "strong evidence" in cause
    assert "network triage" in cause
    assert "does not grant executable authority" in cause
