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
    assert 'placeholder="qwrh1_' not in action_text

    # The browser must mirror server capability freshness and exact-action gating.
    assert "agentCapabilityFresh" in action_text
    assert "CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000" in action_text
    assert "CAPABILITY_FUTURE_SKEW_MS = 30 * 1000" in action_text
    assert "agentEnablesAction" in action_text
    assert "eligibleAgentsFor" in action_text
    assert "agent.enabled_actions.includes(actionType)" in action_text
    assert "or its capability report is stale" in action_text
    assert 'LEGACY_CAPABILITY_EXEMPT_ACTIONS = new Set(["restart_quietward_demo_service"])' in action_text

    # Agents console makes current trust state explicit rather than showing only a
    # timestamp that an analyst has to interpret manually.
    assert "capabilityStatus" in agents_text
    assert 'type CapabilityStatus = "Fresh" | "Stale" | "Never reported"' in agents_text
    assert "CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000" in agents_text
    assert "CAPABILITY_FUTURE_SKEW_MS = 30 * 1000" in agents_text
    assert "Run the official Response-agent poll path to refresh before response actions" in agents_text
    assert "enabled_actions" in agents_text

    assert "Planned · not executable" in plan_text
    assert "Blocked · future capability" in plan_text
    assert "Planned and manual steps are guidance, not hidden remote commands" in plan_text
    assert "Executable actions:" in plan_text
