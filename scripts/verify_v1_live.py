#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"


def _python() -> str:
    for candidate in (
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _json_request(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Any:
    body = None
    resolved_headers = dict(headers or {})
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        resolved_headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=body, method=method, headers=resolved_headers)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise RuntimeError(f"{method} {url} failed: {exc}") from exc
    return json.loads(raw) if raw else None


def _wait_for_health(api_url: str, process: subprocess.Popen[Any]) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"API exited early with code {process.returncode}")
        try:
            health = _json_request(api_url + "/health")
            if health.get("status") == "ok":
                return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("timed out waiting for QuietWard Response health")


def _enroll(api_url: str, token: str, host_id: str) -> dict[str, Any]:
    value = _json_request(
        api_url + "/api/v1/agents/enroll",
        method="POST",
        headers={"X-QWR-Enrollment-Token": token},
        payload={
            "host_id": host_id,
            "display_name": f"QuietWard v1 acceptance on {host_id}",
            "agent_version": "v1-acceptance",
        },
    )
    if not isinstance(value, dict) or not value.get("secret"):
        raise RuntimeError("agent enrollment returned an invalid response")
    return value


def _load_quietward(quietward_repo: Path):
    source = quietward_repo / "src"
    if not (source / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    sys.path.insert(0, str(source))
    from quietward.pipeline import SentinelPipeline
    from quietward.response_client import QuietWardResponseClient, ResponseClientConfig

    return SentinelPipeline, QuietWardResponseClient, ResponseClientConfig


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the real local QuietWard -> Response -> QuietWard v1 acceptance loop."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward_repo = args.quietward_repo.resolve()
    SentinelPipeline, QuietWardResponseClient, ResponseClientConfig = _load_quietward(
        quietward_repo
    )

    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)
    host_id = "quietward-v1-acceptance-host"

    with tempfile.TemporaryDirectory(prefix="qwr-v1-live-") as temporary:
        state_dir = Path(temporary) / "quietward-state"
        database = Path(temporary) / "response.db"
        env = os.environ.copy()
        env.update(
            {
                "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "QWR_ENROLLMENT_TOKEN": token,
                "QWR_API_HOST": "127.0.0.1",
                "QWR_API_PORT": str(port),
                "QWR_CORS_ORIGINS": "[]",
                "QWR_LOG_LEVEL": "WARNING",
            }
        )

        # Apply the same migration path used by normal startup before launching.
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
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=BACKEND,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            _wait_for_health(api_url, process)
            enrollment = _enroll(api_url, token, host_id)
            client = QuietWardResponseClient(
                ResponseClientConfig(
                    base_url=api_url,
                    agent_id=enrollment["agent_id"],
                    key_id=enrollment["key_id"],
                    secret=enrollment["secret"],
                    host_id=host_id,
                    state_dir=state_dir,
                    timeout_seconds=5.0,
                )
            )

            fixture = client.initialize_demo_fixture(unhealthy=True)
            delivery = client.deliver_cycle([], SentinelPipeline().analyze([]))
            if delivery != {"sent": 1, "queued": 0}:
                raise RuntimeError(f"unexpected signed demo-event delivery: {delivery}")

            incidents = _json_request(api_url + "/api/v1/incidents")
            if not isinstance(incidents, list) or len(incidents) != 1:
                raise RuntimeError(f"expected exactly one incident, got: {incidents!r}")
            incident_id = incidents[0]["incident_id"]
            detail = _json_request(api_url + f"/api/v1/incidents/{incident_id}")
            controlled = [
                item
                for item in detail.get("recommended_actions", [])
                if item.get("registry_action_type") == "restart_quietward_demo_service"
                and item.get("enabled") is True
            ]
            if len(controlled) != 1:
                raise RuntimeError("controlled demo recommendation was not produced")

            action = _json_request(
                api_url + f"/api/v1/incidents/{incident_id}/actions",
                method="POST",
                headers={"X-Actor-ID": "v1-acceptance"},
                payload={
                    "target_agent_id": enrollment["agent_id"],
                    "target_host_id": host_id,
                    "action_type": "restart_quietward_demo_service",
                    "parameters": {},
                },
            )
            if action.get("status") != "pending":
                raise RuntimeError(f"action did not require approval: {action!r}")

            approved = _json_request(
                api_url + f"/api/v1/actions/{action['action_id']}/approve",
                method="POST",
                headers={"X-Actor-ID": "v1-acceptance"},
                payload={"reason": "controlled v1 acceptance fixture"},
            )
            if approved.get("status") != "approved" or approved.get("policy_allowed") is not True:
                raise RuntimeError(f"action approval/policy failed: {approved!r}")

            executed = client.poll_and_execute()
            if executed != 1:
                raise RuntimeError(f"expected one local demo action execution, got {executed}")

            actions = _json_request(api_url + f"/api/v1/incidents/{incident_id}/actions")
            if not isinstance(actions, list) or actions[0].get("status") != "succeeded":
                raise RuntimeError(f"terminal action result not stored: {actions!r}")

            state = json.loads(fixture.read_text(encoding="utf-8"))
            if state.get("status") != "running" or state.get("restart_count") != 1:
                raise RuntimeError(f"demo fixture did not transition exactly once: {state!r}")

            # A second poll proves terminal replay does not execute the action again.
            if client.poll_and_execute() != 0:
                raise RuntimeError("terminal action was unexpectedly re-executed")
            state_after_retry = json.loads(fixture.read_text(encoding="utf-8"))
            if state_after_retry.get("restart_count") != 1:
                raise RuntimeError("demo fixture restart count changed on replay")

            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True or int(audit.get("entries_checked", 0)) < 1:
                raise RuntimeError(f"audit chain failed verification: {audit!r}")

            print("V1 LIVE TWO-REPOSITORY ACCEPTANCE: PASS")
            print(f"incident_id={incident_id}")
            print(f"action_id={action['action_id']}")
            print(f"audit_entries={audit['entries_checked']}")
            print(f"audit_head={audit['head_hash']}")
            return 0
        finally:
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
