from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.response_agent import AgentConfig, ResponseAgent, ResponseAgentError
from scripts.response_agent_resources import (
    ResourceError,
    ResourceHandleStore,
    _linux_process,
    _windows_processes,
    collect_file_diagnostic,
    quarantine_file_by_handle,
    restore_quarantined_file,
    terminate_process_by_handle,
)


def _snapshot_pid(pid: int):
    if os.name == "nt":
        return next((item for item in _windows_processes() if int(item["pid"]) == pid), None)
    if sys.platform.startswith("linux"):
        return _linux_process(pid)
    return None


def _agent_config(tmp_path: Path, managed_root: Path | None = None) -> AgentConfig:
    roots = (managed_root,) if managed_root is not None else ()
    return AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-v12",
        key_id="key-v12",
        secret="test-secret-v12",
        host_id="host-v12",
        state_dir=(tmp_path / "state").resolve(),
        managed_roots=roots,
        quarantine_dir=(tmp_path / "quarantine").resolve(),
        enable_process_termination=True,
        enable_file_quarantine=True,
    )


def _action(
    *,
    action_type: str,
    incident_id: str,
    parameters: dict,
    action_id: str = "00000000-0000-0000-0000-000000000001",
) -> dict:
    now = time.time()
    from datetime import datetime, timezone

    requested = datetime.fromtimestamp(now, timezone.utc)
    expires = datetime.fromtimestamp(now + 300, timezone.utc)
    return {
        "schema_version": "1.0",
        "action_id": action_id,
        "incident_id": incident_id,
        "target_agent_id": "agent-v12",
        "target_host_id": "host-v12",
        "action_type": action_type,
        "parameters": parameters,
        "requested_at": requested.isoformat(),
        "requested_by": "analyst-test",
        "approval_id": "00000000-0000-0000-0000-000000000002",
        "expires_at": expires.isoformat(),
        "status": "dispatching",
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": requested.isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }


def test_managed_file_quarantine_and_restore_are_handle_bound(tmp_path: Path) -> None:
    managed = (tmp_path / "managed").resolve()
    managed.mkdir()
    source = managed / "sample.bin"
    source.write_bytes(b"safe disposable test fixture")
    store = ResourceHandleStore((tmp_path / "state").resolve())

    diagnostic = collect_file_diagnostic(store, (managed,))
    assert diagnostic["read_only"] is True
    assert diagnostic["system_state_changed"] is False
    row = next(item for item in diagnostic["files"] if item["relative_path"] == "sample.bin")
    assert "resource_handle" in row
    assert str(source) not in str(diagnostic)

    quarantined = quarantine_file_by_handle(
        store,
        row["resource_handle"],
        (tmp_path / "quarantine").resolve(),
    )
    assert quarantined["quarantined"] is True
    assert quarantined["reversible"] is True
    assert not source.exists()

    # Exact replay returns the stored consumption receipt instead of moving again.
    assert quarantine_file_by_handle(
        store,
        row["resource_handle"],
        (tmp_path / "quarantine").resolve(),
    ) == quarantined

    restored = restore_quarantined_file(
        store,
        quarantined["rollback_resource_handle"],
    )
    assert restored["restored"] is True
    assert source.read_bytes() == b"safe disposable test fixture"
    assert restore_quarantined_file(
        store,
        quarantined["rollback_resource_handle"],
    ) == restored


def test_file_identity_change_and_occupied_restore_fail_closed(tmp_path: Path) -> None:
    managed = (tmp_path / "managed").resolve()
    managed.mkdir()
    source = managed / "artifact.bin"
    source.write_bytes(b"version-one")
    store = ResourceHandleStore((tmp_path / "state").resolve())
    diagnostic = collect_file_diagnostic(store, (managed,))
    handle = diagnostic["files"][0]["resource_handle"]

    source.write_bytes(b"version-two-with-a-different-size")
    with pytest.raises(ResourceError, match="identity changed"):
        quarantine_file_by_handle(store, handle, (tmp_path / "quarantine").resolve())

    diagnostic = collect_file_diagnostic(store, (managed,))
    handle = diagnostic["files"][0]["resource_handle"]
    quarantined = quarantine_file_by_handle(store, handle, (tmp_path / "quarantine").resolve())
    source.write_bytes(b"replacement occupying original path")
    with pytest.raises(ResourceError, match="original path is occupied"):
        restore_quarantined_file(store, quarantined["rollback_resource_handle"])


def test_symlink_is_not_eligible_for_managed_file_handle(tmp_path: Path) -> None:
    managed = (tmp_path / "managed").resolve()
    managed.mkdir()
    target = managed / "target.bin"
    target.write_bytes(b"target")
    link = managed / "link.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")

    diagnostic = collect_file_diagnostic(
        ResourceHandleStore((tmp_path / "state").resolve()),
        (managed,),
    )
    names = {item["relative_path"] for item in diagnostic["files"]}
    assert "target.bin" in names
    assert "link.bin" not in names


@pytest.mark.skipif(
    not (os.name == "nt" or sys.platform.startswith("linux")),
    reason="process containment is currently Windows/Linux only",
)
def test_disposable_child_process_termination_is_exact_and_replay_safe(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.time() + 5
        snapshot = None
        while time.time() < deadline and snapshot is None:
            snapshot = _snapshot_pid(child.pid)
            if snapshot is None:
                time.sleep(0.05)
        assert snapshot is not None

        store = ResourceHandleStore((tmp_path / "state").resolve())
        issued = store.issue(
            kind="process",
            identity=dict(snapshot["identity"]),
            fingerprint=str(snapshot["fingerprint"]),
            display={
                "pid": snapshot["pid"],
                "parent_pid": snapshot["parent_pid"],
                "image": snapshot["image"],
            },
        )
        result = terminate_process_by_handle(store, issued["resource_handle"])
        assert result["termination_requested"] is True
        child.wait(timeout=5)
        assert child.poll() is not None
        assert terminate_process_by_handle(store, issued["resource_handle"]) == result
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_agent_binds_handles_to_originating_incident(tmp_path: Path) -> None:
    managed = (tmp_path / "managed").resolve()
    managed.mkdir()
    (managed / "artifact.bin").write_bytes(b"fixture")
    agent = ResponseAgent(_agent_config(tmp_path, managed))

    diagnostic_action = _action(
        action_type="collect_file_diagnostic",
        incident_id="incident-a",
        parameters={},
    )
    diagnostic_result = agent._execute_action(diagnostic_action, recover_after_started=False)
    agent._bind_result_handles(diagnostic_action, diagnostic_result)
    handle = diagnostic_result["files"][0]["resource_handle"]

    same_incident = _action(
        action_type="quarantine_artifact_by_handle",
        incident_id="incident-a",
        parameters={"resource_handle": handle},
        action_id="00000000-0000-0000-0000-000000000003",
    )
    assert agent._validate_action(same_incident, {}) == same_incident["action_id"]

    different_incident = dict(same_incident)
    different_incident["action_id"] = "00000000-0000-0000-0000-000000000004"
    different_incident["incident_id"] = "incident-b"
    with pytest.raises(ResponseAgentError, match="different incident"):
        agent._validate_action(different_incident, {})


def test_high_impact_agent_capabilities_are_opt_in(tmp_path: Path) -> None:
    config = AgentConfig(
        base_url="http://127.0.0.1:8002",
        agent_id="agent-v12",
        key_id="key-v12",
        secret="test-secret-v12",
        host_id="host-v12",
        state_dir=(tmp_path / "state").resolve(),
    )
    capabilities = ResponseAgent(config).capabilities()
    assert capabilities["mutating_actions"]["terminate_process_by_handle"] is False
    assert capabilities["mutating_actions"]["quarantine_artifact_by_handle"] is False
    assert capabilities["arbitrary_command_execution"] is False
    assert capabilities["resource_handles_are_incident_bound"] is True
