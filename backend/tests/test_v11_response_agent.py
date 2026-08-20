from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.response_agent import AgentConfig, ResponseAgent, ResponseAgentError


def _config(tmp_path: Path) -> AgentConfig:
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-alpha",
        key_id="key-alpha",
        secret="alpha-secret",
        host_id="host-alpha",
        state_dir=tmp_path,
    )


def _action(**overrides):
    now = datetime.now(timezone.utc)
    value = {
        "schema_version": "1.0",
        "action_id": "00000000-0000-0000-0000-000000000001",
        "incident_id": "00000000-0000-0000-0000-000000000002",
        "target_agent_id": "agent-alpha",
        "target_host_id": "host-alpha",
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
        "requested_at": now.isoformat(),
        "requested_by": "alpha-test",
        "approval_id": "00000000-0000-0000-0000-000000000003",
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "status": "dispatching",
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": now.isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }
    value.update(overrides)
    return value


class FakeResponseAgent(ResponseAgent):
    def __init__(self, config: AgentConfig, actions: list[dict]) -> None:
        super().__init__(config)
        self.actions = actions
        self.results: list[dict] = []

    def _request(self, method: str, target: str, payload=None):
        if method == "GET" and target.endswith("/actions/pending"):
            return self.actions
        if method == "POST" and target.endswith("/result"):
            self.results.append(dict(payload or {}))
            return {"ok": True}
        raise AssertionError((method, target))


def test_response_agent_allowlist_rejects_target_and_parameter_substitution(tmp_path: Path) -> None:
    agent = ResponseAgent(_config(tmp_path))
    agent.initialize_demo_fixture(unhealthy=True)
    ledger: dict[str, dict] = {}

    assert agent._validate_action(_action(), ledger) == _action()["action_id"]

    with pytest.raises(ResponseAgentError, match="another host"):
        agent._validate_action(_action(target_host_id="other-host"), ledger)
    with pytest.raises(ResponseAgentError, match="not allowlisted"):
        agent._validate_action(_action(action_type="run_shell"), ledger)
    with pytest.raises(ResponseAgentError, match="accepts no parameters"):
        agent._validate_action(_action(parameters={"command": "whoami"}), ledger)
    with pytest.raises(ResponseAgentError, match="not policy-allowed"):
        agent._validate_action(_action(policy_allowed=False), ledger)


def test_demo_fixture_action_is_exactly_once_locally(tmp_path: Path) -> None:
    agent = ResponseAgent(_config(tmp_path))
    agent.initialize_demo_fixture(unhealthy=True)
    action_id = _action()["action_id"]

    first = agent._apply_demo_action(action_id)
    second = agent._apply_demo_action(action_id)
    assert first == second

    state = json.loads(agent.demo_state_path.read_text(encoding="utf-8"))
    assert state["status"] == "running"
    assert state["restart_count"] == 1
    assert state["last_action_id"] == action_id


def test_poll_once_persists_terminal_result_and_does_not_reexecute(tmp_path: Path) -> None:
    action = _action()
    agent = FakeResponseAgent(_config(tmp_path), [action])
    agent.initialize_demo_fixture(unhealthy=True)

    assert agent.poll_once() == 1
    assert [item["status"] for item in agent.results] == ["executing", "succeeded"]

    # The same delivered action is reconciled from the terminal ledger rather than
    # changing the demo fixture again.
    assert agent.poll_once() == 0
    assert agent.results[-1]["status"] == "succeeded"
    state = json.loads(agent.demo_state_path.read_text(encoding="utf-8"))
    assert state["restart_count"] == 1


def test_server_only_executing_state_requires_local_history(tmp_path: Path) -> None:
    agent = ResponseAgent(_config(tmp_path))
    agent.initialize_demo_fixture(unhealthy=True)
    with pytest.raises(ResponseAgentError, match="without matching local execution history"):
        agent._validate_action(_action(status="executing"), {})


def test_agent_source_has_no_generic_host_execution_primitive() -> None:
    source = (Path(__file__).resolve().parents[2] / "scripts" / "response_agent.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "import subprocess",
        "subprocess.run",
        "subprocess.Popen",
        "os.system",
        "shell=True",
        "powershell.exe",
        "cmd.exe",
    ):
        assert forbidden not in source
