from __future__ import annotations

from scripts.audit_public_release import _is_blocked_path


def test_agent_credentials_and_rotation_sidecars_are_release_blocked() -> None:
    for path in (
        "agent.json",
        "response-agent.json",
        "response-agent-config.json",
        "agent.json.next",
        "response-agent.json.next",
        "response-agent-config.json.next",
        "private/agent.json.next",
    ):
        reason = _is_blocked_path(path)
        assert reason is not None, path
        assert "credential" in reason.lower()


def test_github_actions_workflows_are_blocked_from_current_release_tree_only() -> None:
    reason = _is_blocked_path(".github/workflows/ci.yml", current_tree=True)
    assert reason is not None
    assert "github actions" in reason.lower()
    assert _is_blocked_path(".github/workflows/old-qualification.yml", current_tree=False) is None


def test_noncredential_next_file_is_not_overblocked() -> None:
    assert _is_blocked_path("docs/roadmap.md.next") is None
