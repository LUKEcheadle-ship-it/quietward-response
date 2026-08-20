#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from verify_v1_live import (
    BACKEND,
    _enroll,
    _free_port,
    _json_request,
    _python,
    _wait_for_health,
)


def _load_quietward(quietward_repo: Path):
    source = quietward_repo / "src"
    if not (source / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    sys.path.insert(0, str(source))
    from quietward.contracts import EventKind, SecurityEvent
    from quietward.pipeline import SentinelPipeline
    from quietward.response_client import ResponseClientConfig
    from quietward.response_client_v11 import ExpandedQuietWardResponseClient

    return (
        EventKind,
        SecurityEvent,
        SentinelPipeline,
        ResponseClientConfig,
        ExpandedQuietWardResponseClient,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the real QuietWard v1.1 diagnostic-response alpha loop."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward_repo = args.quietward_repo.resolve()
    (
        EventKind,
        SecurityEvent,
        SentinelPipeline,
        ResponseClientConfig,
        ExpandedQuietWardResponseClient,
    ) = _load_quietward(quietward_repo)

    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)
    host_id = "quietward-v11-alpha-host"

    with tempfile.TemporaryDirectory(prefix="qwr-v11-alpha-live-") as temporary:
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
            enrollment = _enroll(api_url, token, host_id)
            client = ExpandedQuietWardResponseClient(
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

            event = SecurityEvent(
                event_id="alpha-malware-diagnostic-event",
                observed_at=datetime.now(timezone.utc),
                host_id=host_id,
                source="alpha-acceptance",
                kind=EventKind.MALWARE_SIGNATURE,
                subject="/tmp/quietward-alpha-malware-fixture",
                attributes={
                    "signature": "alpha-test-signature",
                    "authoritative_scanner_detection": True,
                    "raw_scanner_output_persisted": False,
                    "test_owned": True,
                },
                confidence=1.0,
            )
            report = SentinelPipeline().analyze([event])
            delivery = client.deliver_cycle([event], report)
            if delivery != {"sent": 1, "queued": 0}:
                raise RuntimeError(f"unexpected signed event delivery: {delivery}")

            incidents = _json_request(api_url + "/api/v1/incidents")
            if not isinstance(incidents, list) or len(incidents) != 1:
                raise RuntimeError(f"expected one incident, got: {incidents!r}")
            incident_id = incidents[0]["incident_id"]
            detail = _json_request(api_url + f"/api/v1/incidents/{incident_id}")
            controlled = [
                item
                for item in detail.get("recommended_actions", [])
                if item.get("registry_action_type") == "collect_file_diagnostic"
                and item.get("enabled") is True
            ]
            if len(controlled) != 1:
                raise RuntimeError("file diagnostic recommendation was not produced")

            action = _json_request(
                api_url + f"/api/v1/incidents/{incident_id}/actions",
                method="POST",
                headers={"X-Actor-ID": "v11-alpha-acceptance"},
                payload={
                    "target_agent_id": enrollment["agent_id"],
                    "target_host_id": host_id,
                    "action_type": "collect_file_diagnostic",
                    "parameters": {},
                },
            )
            if action.get("status") != "pending":
                raise RuntimeError(f"diagnostic did not require approval: {action!r}")

            approved = _json_request(
                api_url + f"/api/v1/actions/{action['action_id']}/approve",
                method="POST",
                headers={"X-Actor-ID": "v11-alpha-acceptance"},
                payload={"reason": "collect bounded alpha diagnostic evidence"},
            )
            if approved.get("status") != "approved" or approved.get("policy_allowed") is not True:
                raise RuntimeError(f"diagnostic approval/policy failed: {approved!r}")

            demo_count = client.poll_and_execute()
            if demo_count != 0:
                raise RuntimeError("read-only diagnostic was counted as demo remediation")
            if client.last_execution_counts.get("collect_file_diagnostic") != 1:
                raise RuntimeError(
                    f"diagnostic execution was not recorded: {client.last_execution_counts!r}"
                )

            actions = _json_request(api_url + f"/api/v1/incidents/{incident_id}/actions")
            stored = next(item for item in actions if item["action_id"] == action["action_id"])
            if stored.get("status") != "succeeded":
                raise RuntimeError(f"diagnostic result not terminal: {stored!r}")
            result = stored.get("result") or {}
            if result.get("read_only") is not True or result.get("system_state_changed") is not False:
                raise RuntimeError(f"diagnostic safety metadata is invalid: {result!r}")
            if int(result.get("matched_event_count", 0)) < 1:
                raise RuntimeError(f"diagnostic returned no matching evidence: {result!r}")
            returned_ids = {
                item.get("event_id")
                for item in result.get("events", [])
                if isinstance(item, dict)
            }
            if event.event_id not in returned_ids:
                raise RuntimeError("diagnostic omitted the triggering QuietWard event")

            if client.poll_and_execute() != 0:
                raise RuntimeError("terminal diagnostic action was unexpectedly re-executed")

            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True or int(audit.get("entries_checked", 0)) < 1:
                raise RuntimeError(f"audit chain failed verification: {audit!r}")

            print("V1.1.0-ALPHA.1 LIVE DIAGNOSTIC ACCEPTANCE: PASS")
            print(f"incident_id={incident_id}")
            print(f"action_id={action['action_id']}")
            print(f"diagnostic_events={result['matched_event_count']}")
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
