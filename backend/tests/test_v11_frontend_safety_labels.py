from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_ui_separates_guidance_diagnostics_and_handle_bound_actions() -> None:
    action_text = (
        ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx"
    ).read_text(encoding="utf-8")
    plan_text = (
        ROOT / "frontend" / "src" / "components" / "ResponsePlanPanel.tsx"
    ).read_text(encoding="utf-8")
    agents_text = (
        ROOT / "frontend" / "src" / "app" / "agents" / "page.tsx"
    ).read_text(encoding="utf-8")

    assert "Read-only diagnostic · Approval required" in action_text
    assert "High-impact containment · Opaque handle · Approval required" in action_text
    assert "Reversible containment · Opaque handle · Approval required" in action_text
    assert "Rollback · Opaque handle · Approval required" in action_text
    assert "Only handles returned by this incident and selected agent are offered" in action_text
    assert "Raw PIDs and file paths cannot be entered" in action_text
    assert "Run the matching diagnostic/action first" in action_text
    assert "raw PIDs, paths, commands, service names, firewall rules" in action_text
    assert "handleOptionsFor" in action_text
    assert "qwrh1_" in action_text
    assert "placeholder=\"qwrh1_" not in action_text

    # The browser must not offer a non-demo action on an agent that has not
    # independently signed that exact capability as locally enabled.
    assert "agentEnablesAction" in action_text
    assert "eligibleAgentsFor" in action_text
    assert "agent.capabilities_updated_at && agent.enabled_actions.includes(actionType)" in action_text
    assert "No affected Response agent has signed this action as enabled" in action_text
    assert 'LEGACY_CAPABILITY_EXEMPT_ACTIONS = new Set(["restart_quietward_demo_service"])' in action_text

    assert "signed its locally enabled action capabilities" in agents_text
    assert "capabilities_updated_at" in agents_text
    assert "enabled_actions" in agents_text

    assert "Planned · not executable" in plan_text
    assert "Blocked · future capability" in plan_text
    assert "Planned and manual steps are guidance, not hidden remote commands" in plan_text
    assert "Executable actions:" in plan_text
