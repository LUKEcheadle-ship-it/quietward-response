"""Integrated vNext keeps the four legacy actions unchanged and permits only its two already-declared additions."""
from app.services.action_registry import ACTION_REGISTRY


def test_maintenance_retains_parameterless_approval_gated_actions():
    legacy = {
        'restart_quietward_demo_service', 'collect_host_diagnostic',
        'collect_process_diagnostic', 'collect_network_diagnostic',
    }
    assert set(ACTION_REGISTRY) == legacy | {"collect_incident_triage_bundle", "terminate_evidence_process"}
    for name in legacy:
        definition = ACTION_REGISTRY[name]
        assert definition.approval_required is True
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({'pid': 999999})
        assert definition.validate_parameters({'command': 'not-executed'})

    containment = ACTION_REGISTRY["terminate_evidence_process"]
    assert containment.approval_required and containment.risk_level == "high"
    assert containment.validate_parameters({"pid": 999999})
    assert containment.validate_parameters({"command": "not-executed"})
