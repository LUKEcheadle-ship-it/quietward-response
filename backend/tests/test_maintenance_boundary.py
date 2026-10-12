"""Maintenance must not promote the unrelated process-control feature branch."""
from app.services.action_registry import ACTION_REGISTRY


def test_maintenance_retains_parameterless_approval_gated_actions():
    assert set(ACTION_REGISTRY) == {
        'restart_quietward_demo_service', 'collect_host_diagnostic',
        'collect_process_diagnostic', 'collect_network_diagnostic',
    }
    for definition in ACTION_REGISTRY.values():
        assert definition.approval_required is True
        assert definition.validate_parameters({}) == []
        assert definition.validate_parameters({'pid': 999999})
        assert definition.validate_parameters({'command': 'not-executed'})
