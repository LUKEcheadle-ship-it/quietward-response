#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from response_agent import AgentConfig, ResponseAgent
from verify_v1_live import BACKEND, _free_port, _json_request, _python, _wait_for_health


EXPECTED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "terminate_process_by_handle",
    "collect_file_diagnostic",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
}


def _event(host_id: str, event_type: str, category: str, severity: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "v12-live-acceptance-sensor",
        "source_version": "1.0",
        "host_id": host_id,
        "host_name": host_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "confidence": 1.0,
        "summary": f"Synthetic {event_type} v1.2 acceptance evidence",
        "evidence": {"synthetic": True, "v12_acceptance": True},
        "metadata": {"operating_system": "Linux"},
    }


def _enroll(api_url: str, token: str, host_id: str) -> dict[str, Any]:
    value = _json_request(
        api_url + "/api/v1/agents/enroll",
        method="POST",
        headers={"X-QWR-Enrollment-Token": token},
        payload={
            "host_id": host_id,
            "display_name": f"Response v1.2 acceptance agent on {host_id}",
            "agent_version": "1.2.0-alpha.1-acceptance",
        },
    )
    if not isinstance(value, dict) or not value.get("secret"):
        raise RuntimeError("agent enrollment returned an invalid response")
    return value


def _create_incident(api_url: str, host_id: str, event_type: str, category: str, severity: str) -> str:
    created = _json_request(
        api_url + "/api/v1/events",
        method="POST",
        payload=_event(host_id, event_type, category, severity),
    )
    return str(created["incident_id"])


def _create_action(
    api_url: str,
    incident_id: str,
    enrollment: dict[str, Any],
    host_id: str,
    action_type: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    return _json_request(
        api_url + f"/api/v1/incidents/{incident_id}/actions",
        method="POST",
        headers={"X-Actor-ID": "v12-live-analyst"},
        payload={
            "target_agent_id": enrollment["agent_id"],
            "target_host_id": host_id,
            "action_type": action_type,
            "parameters": parameters,
        },
    )


def _approve(api_url: str, action_id: str) -> dict[str, Any]:
    approved = _json_request(
        api_url + f"/api/v1/actions/{action_id}/approve",
        method="POST",
        headers={"X-Actor-ID": "v12-live-analyst"},
        payload={"reason": "v1.2 standalone live acceptance"},
    )
    if approved.get("status") != "approved" or approved.get("policy_allowed") is not True:
        raise RuntimeError(f"action approval/policy failed: {approved!r}")
    return approved


def _stored_action(api_url: str, incident_id: str, action_id: str) -> dict[str, Any]:
    rows = _json_request(api_url + f"/api/v1/incidents/{incident_id}/actions")
    return next(item for item in rows if item["action_id"] == action_id)


def _run_agent_action(
    api_url: str,
    agent: ResponseAgent,
    incident_id: str,
    enrollment: dict[str, Any],
    host_id: str,
    action_type: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    created = _create_action(
        api_url,
        incident_id,
        enrollment,
        host_id,
        action_type,
        parameters,
    )
    if created.get("status") != "pending":
        raise RuntimeError(f"action did not enter pending approval: {created!r}")
    _approve(api_url, str(created["action_id"]))
    completed = agent.poll_once()
    if completed != 1:
        raise RuntimeError(f"agent did not complete exactly one new action: {completed}")
    stored = _stored_action(api_url, incident_id, str(created["action_id"]))
    if stored.get("status") != "succeeded":
        raise RuntimeError(f"action did not succeed: {stored!r}")
    return stored


def _expect_rejected(callable_, phrase: str) -> None:
    try:
        callable_()
    except RuntimeError as exc:
        if phrase not in str(exc):
            raise
    else:
        raise RuntimeError(f"request unexpectedly succeeded; expected rejection containing {phrase!r}")


def main() -> int:
    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)

    with tempfile.TemporaryDirectory(prefix="qwr-v12-live-") as temporary:
        root = Path(temporary)
        database = root / "response.db"
        env = os.environ.copy()
        env.update(
            {
                "QWR_ENVIRONMENT": "development",
                "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "QWR_ENROLLMENT_TOKEN": token,
                "QWR_API_HOST": "127.0.0.1",
                "QWR_API_PORT": str(port),
                "QWR_CORS_ORIGINS": "[]",
                "QWR_LOG_LEVEL": "WARNING",
                "QWR_API_RATE_LIMIT_PER_MINUTE": "600",
            }
        )

        subprocess.run(
            [python, "-m", "alembic", "upgrade", "head"],
            cwd=BACKEND,
            env=env,
            check=True,
        )
        process = subprocess.Popen(
            [
                python,
                "-m",
                "uvicorn",
                "app.main:runtime_app",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--workers",
                "1",
            ],
            cwd=BACKEND,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        child: subprocess.Popen[Any] | None = None
        try:
            _wait_for_health(api_url, process)

            registry = _json_request(api_url + "/api/v1/actions/registry")
            actual = {item.get("action_type") for item in registry}
            if actual != EXPECTED_ACTIONS:
                raise RuntimeError(f"unexpected executable action registry: {registry!r}")

            # ----- Managed-file quarantine + restore -------------------------
            file_host = "v12-file-host"
            managed = root / "managed"
            managed.mkdir()
            sample = managed / "suspicious-test.bin"
            sample.write_bytes(b"disposable v1.2 quarantine fixture")
            file_enrollment = _enroll(api_url, token, file_host)
            file_agent = ResponseAgent(
                AgentConfig(
                    base_url=api_url,
                    agent_id=file_enrollment["agent_id"],
                    key_id=file_enrollment["key_id"],
                    secret=file_enrollment["secret"],
                    host_id=file_host,
                    state_dir=(root / "file-agent-state").resolve(),
                    managed_roots=(managed.resolve(),),
                    quarantine_dir=(root / "file-quarantine").resolve(),
                    enable_file_quarantine=True,
                )
            )
            file_incident = _create_incident(
                api_url,
                file_host,
                "ransomware_detected",
                "malware",
                "critical",
            )
            file_plan = _json_request(
                api_url + f"/api/v1/incidents/{file_incident}/response-plan"
            )
            for required in (
                "collect_file_diagnostic",
                "quarantine_artifact_by_handle",
                "restore_quarantined_artifact_by_handle",
            ):
                if required not in file_plan.get("executable_actions", []):
                    raise RuntimeError(f"file response plan missing {required}: {file_plan!r}")

            diagnostic = _run_agent_action(
                api_url,
                file_agent,
                file_incident,
                file_enrollment,
                file_host,
                "collect_file_diagnostic",
                {},
            )
            files = (diagnostic.get("result") or {}).get("files") or []
            row = next(item for item in files if item.get("relative_path") == sample.name)
            file_handle = row["resource_handle"]
            if str(sample) in json.dumps(diagnostic.get("result") or {}):
                raise RuntimeError("file diagnostic leaked the managed absolute path")

            _expect_rejected(
                lambda: _create_action(
                    api_url,
                    file_incident,
                    file_enrollment,
                    file_host,
                    "quarantine_artifact_by_handle",
                    {"path": str(sample)},
                ),
                "exactly one resource_handle",
            )

            quarantined = _run_agent_action(
                api_url,
                file_agent,
                file_incident,
                file_enrollment,
                file_host,
                "quarantine_artifact_by_handle",
                {"resource_handle": file_handle},
            )
            if sample.exists():
                raise RuntimeError("managed file remained at original path after quarantine")
            rollback_handle = (quarantined.get("result") or {}).get(
                "rollback_resource_handle"
            )
            if not isinstance(rollback_handle, str) or not rollback_handle.startswith("qwrh1_"):
                raise RuntimeError(f"quarantine did not return rollback handle: {quarantined!r}")

            restored = _run_agent_action(
                api_url,
                file_agent,
                file_incident,
                file_enrollment,
                file_host,
                "restore_quarantined_artifact_by_handle",
                {"resource_handle": rollback_handle},
            )
            if not sample.exists() or sample.read_bytes() != b"disposable v1.2 quarantine fixture":
                raise RuntimeError(f"quarantine rollback failed: {restored!r}")

            # ----- Exact disposable child-process termination ---------------
            process_host = "v12-process-host"
            process_enrollment = _enroll(api_url, token, process_host)
            process_agent = ResponseAgent(
                AgentConfig(
                    base_url=api_url,
                    agent_id=process_enrollment["agent_id"],
                    key_id=process_enrollment["key_id"],
                    secret=process_enrollment["secret"],
                    host_id=process_host,
                    state_dir=(root / "process-agent-state").resolve(),
                    enable_process_termination=True,
                )
            )
            process_incident = _create_incident(
                api_url,
                process_host,
                "privilege_escalation",
                "privilege",
                "high",
            )
            child = subprocess.Popen(
                [python, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            process_diagnostic = _run_agent_action(
                api_url,
                process_agent,
                process_incident,
                process_enrollment,
                process_host,
                "collect_process_diagnostic",
                {},
            )
            process_rows = (process_diagnostic.get("result") or {}).get("processes") or []
            child_row = next(item for item in process_rows if int(item.get("pid") or -1) == child.pid)
            process_handle = child_row.get("resource_handle")
            if not process_handle:
                raise RuntimeError("disposable child process did not receive a resource handle")

            _expect_rejected(
                lambda: _create_action(
                    api_url,
                    process_incident,
                    process_enrollment,
                    process_host,
                    "terminate_process_by_handle",
                    {"pid": child.pid},
                ),
                "exactly one resource_handle",
            )

            terminated = _run_agent_action(
                api_url,
                process_agent,
                process_incident,
                process_enrollment,
                process_host,
                "terminate_process_by_handle",
                {"resource_handle": process_handle},
            )
            child.wait(timeout=5)
            if child.poll() is None or not (terminated.get("result") or {}).get("termination_requested"):
                raise RuntimeError(f"disposable child process was not terminated: {terminated!r}")
            child = None

            _expect_rejected(
                lambda: _create_action(
                    api_url,
                    process_incident,
                    process_enrollment,
                    process_host,
                    "run_shell",
                    {"command": "whoami"},
                ),
                "unsupported action type",
            )

            # A terminal server action must never be executed again on replay.
            if file_agent.poll_once() != 0 or process_agent.poll_once() != 0:
                raise RuntimeError("terminal action was unexpectedly re-executed")

            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True or int(audit.get("entries_checked", 0)) < 1:
                raise RuntimeError(f"audit chain failed verification: {audit!r}")

            print("V1.2.0-ALPHA.1 LIVE CONTAINMENT ACCEPTANCE: PASS")
            print("file_diagnostic_handle=yes")
            print("file_quarantine_restore=yes")
            print("process_diagnostic_handle=yes")
            print("disposable_process_termination=yes")
            print("raw_path_pid_targeting=rejected")
            print("generic_shell_action=rejected")
            print("terminal_replay_exactly_once=yes")
            print(f"audit_entries={audit['entries_checked']}")
            print(f"audit_head={audit['head_hash']}")
            return 0
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.returncode not in {0, -15, 1} and process.stdout is not None:
                print(process.stdout.read(), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
