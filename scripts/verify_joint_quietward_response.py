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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from response_agent import AgentConfig, ResponseAgent
from watch_quietward_handoffs import watch_once


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
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        resolved_headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=body, method=method, headers=resolved_headers)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:4000]
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise RuntimeError(f"{method} {url} failed: {exc}") from exc
    return json.loads(raw) if raw else None


def _wait_for_health(api_url: str, process: subprocess.Popen[Any]) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout is not None else ""
            raise RuntimeError(
                f"Response API exited early with code {process.returncode}: {output[-4000:]}"
            )
        try:
            health = _json_request(api_url + "/health")
            if isinstance(health, dict) and health.get("status") == "ok":
                return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("timed out waiting for QuietWard Response health")


def _load_quietward(quietward_repo: Path):
    source = quietward_repo / "src"
    if not (source / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")
    sys.path.insert(0, str(source))
    from quietward import __version__ as quietward_version
    from quietward.contracts import EventKind, SecurityEvent
    from quietward.integrations.response import build_response_handoff_events
    from quietward.pipeline import SentinelPipeline
    from quietward.privacy_identity import PrivacyIdentity

    return (
        quietward_version,
        EventKind,
        SecurityEvent,
        build_response_handoff_events,
        SentinelPipeline,
        PrivacyIdentity,
    )


def _git_sha(path: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=path,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _enroll(api_url: str, token: str, host_id: str) -> dict[str, Any]:
    value = _json_request(
        api_url + "/api/v1/agents/enroll",
        method="POST",
        headers={"X-QWR-Enrollment-Token": token},
        payload={
            "host_id": host_id,
            "display_name": f"Joint acceptance Response agent on {host_id}",
            "agent_version": "1.1.0-alpha.1",
        },
    )
    if not isinstance(value, dict) or not value.get("secret"):
        raise RuntimeError("agent enrollment returned an invalid response")
    return value


def _handoff_document(
    payloads: list[dict[str, Any]],
    *,
    quietward_version: str,
    host_id: str,
) -> dict[str, Any]:
    if not payloads:
        raise RuntimeError("QuietWard produced no Response handoff events")
    if {item.get("host_id") for item in payloads} != {host_id}:
        raise RuntimeError("QuietWard handoff escaped the expected host binding")
    return {
        "format": "quietward-response-handoff-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_version": quietward_version,
        "source_cycle_id": 1,
        "source_chain_hash": "a" * 64,
        "host_ids": [host_id],
        "events": payloads,
        "safety": {
            "observation_only_source": True,
            "actions_executed": 0,
            "executable_authority": False,
            "raw_finding_subjects_included": False,
            "network_request_performed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a real joint QuietWard -> Response -> endpoint diagnostic acceptance loop."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward_repo = args.quietward_repo.resolve()
    (
        quietward_version,
        EventKind,
        SecurityEvent,
        build_response_handoff_events,
        SentinelPipeline,
        PrivacyIdentity,
    ) = _load_quietward(quietward_repo)

    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    token = secrets.token_urlsafe(32)
    host_id = "quietward-response-joint-acceptance"
    raw_subject = "remote-session:203.0.113.55:443"
    source_chain_hash = "a" * 64

    with tempfile.TemporaryDirectory(prefix="qwr-joint-") as temporary:
        temp = Path(temporary)
        database = temp / "response.db"
        agent_state = (temp / "agent-state").resolve()
        outbox = (temp / "quietward-outbox").resolve()
        archive = (outbox / "processed").resolve()
        outbox.mkdir(parents=True, mode=0o700)
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
            config = AgentConfig(
                base_url=api_url,
                agent_id=enrollment["agent_id"],
                key_id=enrollment["key_id"],
                secret=enrollment["secret"],
                host_id=host_id,
                state_dir=agent_state,
                timeout_seconds=5.0,
            )
            agent = ResponseAgent(config)
            capability_payload = {
                "schema_version": "1.0",
                "agent_version": "1.1.0-alpha.1",
                "supported_actions": sorted(
                    [*agent.capabilities()["read_only_actions"], *agent.capabilities()["mutating_actions"]]
                ),
                "enabled_actions": sorted(
                    [*agent.capabilities()["read_only_actions"], *agent.capabilities()["mutating_actions"]]
                ),
                "arbitrary_command_execution": False,
            }
            registered = agent._request(
                "POST",
                f"/api/v1/agents/{config.agent_id}/capabilities",
                capability_payload,
            )
            if not isinstance(registered, dict) or "collect_host_diagnostic" not in registered.get(
                "enabled_actions", []
            ):
                raise RuntimeError("Response agent capability registration failed")

            observed = datetime.now(timezone.utc)
            event = SecurityEvent(
                event_id="joint-network-event-1",
                observed_at=observed,
                host_id=host_id,
                source="network",
                kind=EventKind.OUTBOUND_CONNECTION,
                subject=raw_subject,
                attributes={"external_destination": True},
                confidence=1.0,
            )
            report = SentinelPipeline().analyze([event])
            if report.actions_executed != 0 or any(
                proposal.executable_in_current_mode for proposal in report.action_proposals
            ):
                raise RuntimeError("QuietWard violated the observation-only joint boundary")
            payloads = build_response_handoff_events(
                report,
                [event],
                privacy_identity=PrivacyIdentity(b"joint-acceptance-privacy-key-material"),
                source_version=quietward_version,
                operating_system="Linux",
                source_cycle_id=1,
                source_chain_hash=source_chain_hash,
            )
            document = _handoff_document(
                payloads,
                quietward_version=quietward_version,
                host_id=host_id,
            )
            serialized = json.dumps(document, sort_keys=True)
            if raw_subject in serialized or "203.0.113.55" in serialized:
                raise RuntimeError("raw QuietWard subject leaked into the Response handoff")
            handoff_path = outbox / "cycle-0000000001-aaaaaaaaaaaaaaaa.json"
            handoff_path.write_text(serialized + "\n", encoding="utf-8")
            try:
                handoff_path.chmod(0o600)
            except OSError:
                pass

            consumed = watch_once(config, outbox, archive, archive_files=10)
            if consumed["files_processed"] != 1 or consumed["events_sent"] != len(payloads):
                raise RuntimeError(f"unexpected handoff consumption result: {consumed!r}")
            if list(outbox.glob("cycle-*.json")):
                raise RuntimeError("consumed handoff remained in the active outbox")

            incidents = _json_request(api_url + "/api/v1/incidents")
            if not isinstance(incidents, list) or len(incidents) != 1:
                raise RuntimeError(f"expected exactly one Response incident, got: {incidents!r}")
            incident_id = incidents[0]["incident_id"]
            detail = _json_request(api_url + f"/api/v1/incidents/{incident_id}")
            quietward_events = [
                item for item in detail.get("events", []) if str(item.get("source") or "").lower() == "quietward"
            ]
            if len(quietward_events) != len(payloads):
                raise RuntimeError("Response incident did not preserve the QuietWard handoff events")
            for stored in quietward_events:
                metadata = stored.get("metadata") or {}
                if metadata.get("quietward_source_cycle_id") != 1:
                    raise RuntimeError("Response lost the QuietWard evidence-chain cycle provenance")
                if metadata.get("quietward_source_chain_hash") != source_chain_hash:
                    raise RuntimeError("Response lost the QuietWard evidence-chain hash provenance")

            controlled = [
                item
                for item in detail.get("recommended_actions", [])
                if item.get("registry_action_type") == "collect_host_diagnostic"
                and item.get("enabled") is True
            ]
            if len(controlled) != 1:
                raise RuntimeError("Response did not recommend the bounded host diagnostic")

            created = _json_request(
                api_url + f"/api/v1/incidents/{incident_id}/actions",
                method="POST",
                headers={"X-Actor-ID": "joint-acceptance"},
                payload={
                    "target_agent_id": config.agent_id,
                    "target_host_id": host_id,
                    "action_type": "collect_host_diagnostic",
                    "parameters": {},
                },
            )
            if created.get("status") != "pending":
                raise RuntimeError("joint diagnostic did not require explicit approval")
            approved = _json_request(
                api_url + f"/api/v1/actions/{created['action_id']}/approve",
                method="POST",
                headers={"X-Actor-ID": "joint-acceptance"},
                payload={"reason": "joint QuietWard/Response acceptance"},
            )
            if approved.get("status") != "approved" or approved.get("policy_allowed") is not True:
                raise RuntimeError(f"joint diagnostic approval/policy failed: {approved!r}")

            executed = agent.poll_once()
            if executed != 1:
                raise RuntimeError(f"expected one endpoint diagnostic execution, got {executed}")
            actions = _json_request(api_url + f"/api/v1/incidents/{incident_id}/actions")
            completed = next(
                (item for item in actions if item.get("action_id") == created["action_id"]),
                None,
            )
            if not isinstance(completed, dict) or completed.get("status") != "succeeded":
                raise RuntimeError(f"joint diagnostic did not complete: {completed!r}")
            result = completed.get("result") or {}
            if result.get("read_only") is not True or result.get("system_state_changed") is not False:
                raise RuntimeError(f"joint diagnostic result is not read-only: {result!r}")
            if agent.poll_once() != 0:
                raise RuntimeError("terminal diagnostic was unexpectedly re-executed")

            audit = _json_request(api_url + "/api/v1/audit/verify")
            if audit.get("valid") is not True or int(audit.get("entries_checked", 0)) < 1:
                raise RuntimeError(f"Response audit chain failed verification: {audit!r}")

            print("JOINT QUIETWARD / RESPONSE ACCEPTANCE: PASS")
            print(f"quietward_sha={_git_sha(quietward_repo)}")
            print(f"response_sha={_git_sha(ROOT)}")
            print(f"quietward_version={quietward_version}")
            print(f"incident_id={incident_id}")
            print(f"diagnostic_action_id={created['action_id']}")
            print(f"handoff_events={len(payloads)}")
            print(f"quietward_source_cycle_id=1")
            print(f"quietward_source_chain_hash={source_chain_hash}")
            print(f"audit_entries={audit['entries_checked']}")
            print("quietward_actions_executed=0")
            print("diagnostic_system_state_changed=false")
            print("raw_subject_crossed_boundary=false")
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
