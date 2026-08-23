#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from response_agent_capabilities import sync_capabilities
from response_agent_v12 import AgentConfig, ResponseAgent
from verify_v1_live import BACKEND, _free_port, _json_request, _python, _wait_for_health
from verify_v12_alpha_live import (
    _create_action,
    _create_incident,
    _enroll,
    _expect_rejected,
    _run_agent_action,
)


def main() -> int:
    if platform.system().lower() != "linux" or not Path("/proc/net").is_dir():
        raise RuntimeError(
            "v1.2 network live qualification requires a Linux host with /proc/net"
        )

    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    enrollment_token = secrets.token_urlsafe(32)

    with tempfile.TemporaryDirectory(prefix="qwr-v12-network-live-") as temporary:
        root = Path(temporary)
        database = root / "response.db"
        env = os.environ.copy()
        env.update(
            {
                "QWR_ENVIRONMENT": "development",
                "QWR_DATABASE_URL": f"sqlite:///{database.as_posix()}",
                "QWR_ENROLLMENT_TOKEN": enrollment_token,
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
        try:
            _wait_for_health(api_url, process)
            host_id = "v12-network-live-host"
            enrollment = _enroll(api_url, enrollment_token, host_id)
            agent = ResponseAgent(
                AgentConfig(
                    base_url=api_url,
                    agent_id=enrollment["agent_id"],
                    key_id=enrollment["key_id"],
                    secret=enrollment["secret"],
                    host_id=host_id,
                    state_dir=(root / "agent-state").resolve(),
                )
            )
            capabilities = sync_capabilities(agent)
            if "collect_network_diagnostic" not in set(
                capabilities.get("enabled_actions") or []
            ):
                raise RuntimeError(
                    f"Linux agent did not advertise network diagnostic: {capabilities!r}"
                )

            incident_id = _create_incident(
                api_url,
                host_id,
                "outbound_connection",
                "network",
                "high",
            )
            plan = _json_request(
                api_url + f"/api/v1/incidents/{incident_id}/response-plan"
            )
            if "collect_network_diagnostic" not in plan.get("executable_actions", []):
                raise RuntimeError(f"network response plan missing diagnostic: {plan!r}")

            _expect_rejected(
                lambda: _create_action(
                    api_url,
                    incident_id,
                    enrollment,
                    host_id,
                    "collect_network_diagnostic",
                    {"remote_address": "203.0.113.10"},
                ),
                "accepts no parameters",
            )

            stored = _run_agent_action(
                api_url,
                agent,
                incident_id,
                enrollment,
                host_id,
                "collect_network_diagnostic",
                {},
            )
            result = stored.get("result") or {}
            if result.get("read_only") is not True:
                raise RuntimeError(f"network diagnostic did not declare read-only: {result!r}")
            if result.get("system_state_changed") is not False:
                raise RuntimeError(f"network diagnostic reported a state change: {result!r}")
            if result.get("raw_network_addresses_returned") is not False:
                raise RuntimeError(f"network diagnostic privacy flag invalid: {result!r}")
            connections = result.get("connections")
            if not isinstance(connections, list) or len(connections) > 256:
                raise RuntimeError("network diagnostic result is not bounded to 256 rows")

            forbidden_public_keys = {
                "local_address",
                "remote_address",
                "uid",
                "inode",
            }
            for row in connections:
                if not isinstance(row, dict):
                    raise RuntimeError("network diagnostic contains a non-object row")
                leaked = forbidden_public_keys & set(row)
                if leaked:
                    raise RuntimeError(f"network diagnostic leaked local-only fields: {sorted(leaked)}")
                handle = row.get("resource_handle")
                if not isinstance(handle, str) or not handle.startswith("qwrh1_"):
                    raise RuntimeError("network diagnostic row is missing an opaque handle")
                address_hash = row.get("remote_address_sha256")
                if address_hash is not None and (
                    not isinstance(address_hash, str) or len(address_hash) != 32
                ):
                    raise RuntimeError("network diagnostic remote-address hash is malformed")

            if agent.poll_once() != 0:
                raise RuntimeError("terminal network diagnostic was unexpectedly re-executed")
            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True:
                raise RuntimeError(f"audit chain failed after network diagnostic: {audit!r}")

            print("V1.2 NETWORK LIVE ACCEPTANCE: PASS")
            print(f"connections_returned={len(connections)}")
            print(f"truncated={bool(result.get('truncated'))}")
            print("raw_network_addresses_returned=no")
            print("server_supplied_network_target=rejected")
            print("terminal_replay=no_reexecution")
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
