#!/usr/bin/env python3
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from verify_v1_live import (
    BACKEND,
    _free_port,
    _json_request,
    _python,
    _wait_for_health,
)


CASES = (
    ("malware_signature", "malware", "critical", "malware"),
    ("privilege_escalation", "privilege", "high", "privilege"),
    ("auth_failure", "identity", "medium", "identity"),
    ("persistence_change", "persistence", "high", "persistence"),
    ("outbound_connection", "network", "high", "network"),
    ("container_escape_indicator", "container", "critical", "container"),
    ("package_vulnerability", "vulnerability", "medium", "vulnerability"),
    ("evidence_integrity_failure", "integrity", "critical", "integrity"),
)


def _event(host_id: str, event_type: str, category: str, severity: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "event_id": str(uuid4()),
        "source": "alpha-acceptance-sensor",
        "source_version": "1.0",
        "host_id": host_id,
        "host_name": host_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "confidence": 1.0,
        "summary": f"Synthetic {category} alpha acceptance evidence",
        "evidence": {"synthetic": True, "alpha_acceptance": True},
        "metadata": {"operating_system": "Test OS"},
    }


def _enroll_alpha_agent(api_url: str, token: str, host_id: str) -> dict[str, Any]:
    value = _json_request(
        api_url + "/api/v1/agents/enroll",
        method="POST",
        headers={"X-QWR-Enrollment-Token": token},
        payload={
            "host_id": host_id,
            "display_name": f"Response alpha acceptance agent on {host_id}",
            "agent_version": "v1.1-alpha-acceptance",
        },
    )
    if not isinstance(value, dict) or not value.get("secret"):
        raise RuntimeError("agent enrollment returned an invalid response")
    return value


def main() -> int:
    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)

    with tempfile.TemporaryDirectory(prefix="qwr-v11-alpha-live-") as temporary:
        database = Path(temporary) / "response.db"
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

            verified_families: list[str] = []
            malware_incident_id: str | None = None
            malware_host_id: str | None = None
            for index, (event_type, category, severity, expected_family) in enumerate(CASES):
                host_id = f"alpha-{expected_family}-{index}"
                created = _json_request(
                    api_url + "/api/v1/events",
                    method="POST",
                    payload=_event(host_id, event_type, category, severity),
                )
                incident_id = created["incident_id"]
                plan = _json_request(
                    api_url + f"/api/v1/incidents/{incident_id}/response-plan"
                )
                if expected_family not in plan.get("attack_families", []):
                    raise RuntimeError(
                        f"response plan missing {expected_family}: {plan!r}"
                    )
                if plan.get("executable_actions") != []:
                    raise RuntimeError(
                        f"non-demo plan exposed executable action: {plan!r}"
                    )
                if not plan.get("investigation_steps"):
                    raise RuntimeError(f"response plan missing investigation steps: {plan!r}")
                verified_families.append(expected_family)
                if expected_family == "malware":
                    malware_incident_id = incident_id
                    malware_host_id = host_id

            if malware_incident_id is None or malware_host_id is None:
                raise RuntimeError("malware acceptance fixture was not created")

            enrollment = _enroll_alpha_agent(api_url, token, malware_host_id)
            try:
                _json_request(
                    api_url + f"/api/v1/incidents/{malware_incident_id}/actions",
                    method="POST",
                    headers={"X-Actor-ID": "v11-alpha-acceptance"},
                    payload={
                        "target_agent_id": enrollment["agent_id"],
                        "target_host_id": malware_host_id,
                        "action_type": "collect_file_diagnostic",
                        "parameters": {},
                    },
                )
            except RuntimeError as exc:
                if "unsupported action type" not in str(exc):
                    raise
            else:
                raise RuntimeError("advisory diagnostic unexpectedly became executable")

            registry = _json_request(api_url + "/api/v1/actions/registry")
            action_types = {item.get("action_type") for item in registry}
            if action_types != {"restart_quietward_demo_service"}:
                raise RuntimeError(f"unexpected executable action registry: {registry!r}")

            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True or int(audit.get("entries_checked", 0)) < 1:
                raise RuntimeError(f"audit chain failed verification: {audit!r}")

            print("V1.1.0-ALPHA.1 LIVE STANDALONE RESPONSE-PLAN ACCEPTANCE: PASS")
            print("response_families=" + ",".join(verified_families))
            print("executable_actions=restart_quietward_demo_service")
            print("unsupported_advisory_action_rejected=yes")
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
