from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_v11_ui_separates_response_guidance_from_executable_actions() -> None:
    action_text = (
        ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx"
    ).read_text(encoding="utf-8")
    plan_text = (
        ROOT / "frontend" / "src" / "components" / "ResponsePlanPanel.tsx"
    ).read_text(encoding="utf-8")

    assert "State-changing demo · Approval required" in action_text
    assert "only executable action" in action_text
    assert "arbitrary command execution is not available" in action_text
    assert "Guidance only" not in action_text

    assert "Planned · not executable" in plan_text
    assert "Blocked · future capability" in plan_text
    assert "Planned and manual steps are guidance, not hidden remote commands" in plan_text
    assert "Executable actions:" in plan_text
