from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from response_agent import AgentConfig, ResponseAgent


def _agent(tmp_path: Path) -> ResponseAgent:
    return ResponseAgent(
        AgentConfig(
            base_url="http://127.0.0.1:8002",
            agent_id="recovery-agent",
            key_id="recovery-key",
            secret="s" * 32,
            host_id="recovery-host",
            state_dir=(tmp_path / "agent-state").resolve(),
        )
    )


def _action(*, status: str = "dispatching") -> dict:
    requested = datetime.now(timezone.utc) - timedelta(seconds=5)
    return {
        "schema_version": "1.0",
        "action_id": "11111111-1111-1111-1111-111111111111",
        "incident_id": "incident-recovery",
        "target_agent_id": "recovery-agent",
        "target_host_id": "recovery-host",
        "action_type": "collect_host_diagnostic",
        "parameters": {},
        "requested_at": requested.isoformat(),
        "requested_by": "analyst",
        "approval_id": "approval-recovery",
        "expires_at": (requested + timedelta(minutes=10)).isoformat(),
        "status": status,
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": requested.isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }


def _capture_requests(agent: ResponseAgent, action: dict):
    posts: list[dict] = []

    def request(method: str, target: str, payload=None):
        if method == "GET":
            return [action]
        assert method == "POST"
        posts.append(dict(payload or {}))
        return {}

    agent._request = request  # type: ignore[method-assign]
    return posts


def test_recovery_reacknowledges_executing_before_rerunning_after_lost_ack(
    tmp_path: Path,
) -> None:
    agent = _agent(tmp_path)
    action = _action(status="dispatching")
    started_at = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    agent._save_ledger(
        {
            action["action_id"]: {
                "status": "executing",
                "action_type": action["action_type"],
                "started_at": started_at,
                "result": {},
                "error": None,
            }
        }
    )
    posts = _capture_requests(agent, action)
    execute = Mock(return_value={"read_only": True, "system_state_changed": False})
    agent._execute = execute  # type: ignore[method-assign]

    assert agent.poll_once() == 1
    execute.assert_called_once_with(action)
    assert [item["status"] for item in posts] == ["executing", "succeeded"]
    assert posts[0]["started_at"] == started_at
    assert posts[1]["started_at"] == started_at


def test_recovery_replays_terminal_result_without_reexecution_when_server_missed_ack(
    tmp_path: Path,
) -> None:
    agent = _agent(tmp_path)
    action = _action(status="dispatching")
    started_at = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    stored_result = {
        "read_only": True,
        "system_state_changed": False,
        "platform": "Linux",
    }
    agent._save_ledger(
        {
            action["action_id"]: {
                "status": "succeeded",
                "action_type": action["action_type"],
                "started_at": started_at,
                "result": stored_result,
                "error": None,
            }
        }
    )
    posts = _capture_requests(agent, action)
    execute = Mock(side_effect=AssertionError("terminal recovery must not re-execute"))
    agent._execute = execute  # type: ignore[method-assign]

    assert agent.poll_once() == 0
    execute.assert_not_called()
    assert [item["status"] for item in posts] == ["executing", "succeeded"]
    assert posts[1]["result"] == stored_result
    assert posts[1]["started_at"] == started_at


def test_terminal_replay_against_server_executing_skips_duplicate_ack(tmp_path: Path) -> None:
    agent = _agent(tmp_path)
    action = _action(status="executing")
    started_at = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
    agent._save_ledger(
        {
            action["action_id"]: {
                "status": "failed",
                "action_type": action["action_type"],
                "started_at": started_at,
                "result": {},
                "error": "bounded diagnostic failed",
            }
        }
    )
    posts = _capture_requests(agent, action)
    execute = Mock(side_effect=AssertionError("terminal recovery must not re-execute"))
    agent._execute = execute  # type: ignore[method-assign]

    assert agent.poll_once() == 0
    execute.assert_not_called()
    assert [item["status"] for item in posts] == ["failed"]
    assert posts[0]["error"] == "bounded diagnostic failed"
