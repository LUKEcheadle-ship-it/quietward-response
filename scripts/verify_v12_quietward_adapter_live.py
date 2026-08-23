#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import time
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from forward_quietward_events import QuietWardEventAdapter
from quietward_adapter_credentials import (
    AdapterCredential,
    EventOnlyClient,
    provision_from_agent_config,
)
from response_agent_v12 import AgentConfig, ResponseAgent
from verify_v1_live import BACKEND, _free_port, _json_request, _python, _wait_for_health
from verify_v12_alpha_live import _enroll


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _quietward_database(path: Path, host_id: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE events(
                event_id TEXT PRIMARY KEY,
                observed_at TEXT NOT NULL,
                host_id TEXT NOT NULL,
                source TEXT NOT NULL,
                kind TEXT NOT NULL,
                subject TEXT NOT NULL,
                severity TEXT,
                score REAL,
                payload_json TEXT NOT NULL
            )
            """
        )
        payload = {
            "event_id": "fse-live-adapter-1",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "host_id": host_id,
            "source": "windows_process_snapshot",
            "kind": "process_start",
            "subject": "powershell.exe",
            "attributes": {
                "pid": 4242,
                "ppid": 100,
                "command_name": "powershell.exe",
                "args_hash": "keyed-command-pseudonym",
                "suspicious_markers": ["reverse_shell"],
                "raw_arguments_persisted": False,
            },
            "confidence": 0.95,
        }
        connection.execute(
            """
            INSERT INTO events(
                event_id,observed_at,host_id,source,kind,subject,severity,score,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                payload["event_id"],
                payload["observed_at"],
                host_id,
                payload["source"],
                payload["kind"],
                payload["subject"],
                "high",
                78.0,
                json.dumps(payload),
            ),
        )
        connection.commit()


def _write_agent_config(path: Path, enrollment: dict, api_url: str, state_dir: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "base_url": api_url,
                "agent_id": enrollment["agent_id"],
                "key_id": enrollment["key_id"],
                "secret": enrollment["secret"],
                "host_id": enrollment["host_id"],
                "state_dir": str(state_dir),
                "managed_roots": [],
                "enable_process_termination": True,
                "enable_file_quarantine": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        path.chmod(0o600)


def _server_rejects_subkey_for_pending(api_url: str, credential: AdapterCredential) -> None:
    target = f"/api/v1/agents/{credential.agent_id}/actions/pending"
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body = b""
    canonical = "\n".join(
        ["GET", target, timestamp, nonce, hashlib.sha256(body).hexdigest()]
    ).encode("utf-8")
    signature = hmac.new(credential.event_subkey, canonical, hashlib.sha256).hexdigest()
    request = Request(
        api_url + target,
        method="GET",
        headers={
            "X-QWR-Agent-ID": credential.agent_id,
            "X-QWR-Key-ID": credential.key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        },
    )
    try:
        urlopen(request, timeout=5).read()
    except HTTPError as exc:
        if exc.code != 401:
            raise RuntimeError(f"event-only subkey rejection returned HTTP {exc.code}") from exc
        return
    raise RuntimeError("event-only subkey unexpectedly authenticated action polling")


def main() -> int:
    python = _python()
    port = _free_port()
    api_url = f"http://127.0.0.1:{port}"
    enrollment_token = secrets.token_urlsafe(32)

    with tempfile.TemporaryDirectory(prefix="qwr-v12-adapter-live-") as temporary:
        root = Path(temporary)
        database = root / "response.db"
        quietward_db = root / "quietward.sqlite3"
        host_id = "v12-adapter-live-host"
        _quietward_database(quietward_db, host_id)
        quietward_before = _sha256(quietward_db)

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
            enrollment = _enroll(api_url, enrollment_token, host_id)
            state_dir = (root / "agent-state").resolve()
            state_dir.mkdir(mode=0o700)
            agent_config_path = (root / "agent.json").resolve()
            adapter_config_path = (root / "adapter.json").resolve()
            _write_agent_config(agent_config_path, enrollment, api_url, state_dir)

            # Endpoint agent retains action authority; adapter receives only the
            # derived event-ingestion key.
            endpoint_agent = ResponseAgent(AgentConfig.from_file(agent_config_path))
            if endpoint_agent.config.secret != enrollment["secret"]:
                raise RuntimeError("endpoint credential load failed")
            provision_from_agent_config(
                agent_config_path,
                adapter_config_path,
                force=False,
            )
            raw_adapter = json.loads(adapter_config_path.read_text(encoding="utf-8"))
            if "secret" in raw_adapter:
                raise RuntimeError("adapter.json copied the endpoint secret")
            if raw_adapter.get("credential_scope") != "quietward_event_ingestion_only":
                raise RuntimeError("adapter credential scope is missing")

            credential = AdapterCredential.from_file(adapter_config_path)
            adapter = QuietWardEventAdapter(
                agent=EventOnlyClient(credential),
                database_path=quietward_db,
                from_beginning=True,
            )
            if adapter.forward_once() != 1:
                raise RuntimeError("QuietWard adapter did not forward exactly one event")
            if _sha256(quietward_db) != quietward_before:
                raise RuntimeError("QuietWard adapter modified the detector database")

            _server_rejects_subkey_for_pending(api_url, credential)

            events = _json_request(api_url + "/api/v1/events?host=" + host_id)
            if not isinstance(events, list) or len(events) != 1:
                raise RuntimeError(f"adapter event was not stored exactly once: {events!r}")
            stored = events[0]
            if stored.get("source") != "quietward":
                raise RuntimeError(f"adapter source identity is wrong: {stored!r}")
            if stored.get("event_type") != "process_start" or stored.get("severity") != "high":
                raise RuntimeError(f"adapter event translation is wrong: {stored!r}")
            evidence = stored.get("evidence") or {}
            if evidence.get("quietward_event_id") != "fse-live-adapter-1":
                raise RuntimeError(f"original QuietWard event ID was not preserved: {stored!r}")
            process_evidence = stored.get("process") or {}
            if "reverse_shell" not in set(process_evidence.get("suspicious_markers") or []):
                raise RuntimeError(f"high-signal QuietWard marker was lost in translation: {stored!r}")

            if adapter.forward_once() != 0:
                raise RuntimeError("adapter replayed an already checkpointed event")
            if _sha256(quietward_db) != quietward_before:
                raise RuntimeError("QuietWard database changed after adapter replay check")

            incidents = _json_request(api_url + "/api/v1/incidents")
            if not incidents:
                raise RuntimeError("adapter event did not create a Response incident")
            incident_id = incidents[0].get("incident_id")
            if not incident_id:
                raise RuntimeError(f"adapter-created incident has no ID: {incidents!r}")
            plan = _json_request(
                api_url + f"/api/v1/incidents/{incident_id}/response-plan"
            )
            executable = set(plan.get("executable_actions") or [])
            if "collect_process_diagnostic" not in executable:
                raise RuntimeError(f"adapter evidence did not enable process diagnosis: {plan!r}")
            if "terminate_process_by_handle" not in executable:
                raise RuntimeError(f"qualified reverse-shell evidence did not enable handle termination: {plan!r}")
            if any(item in executable for item in ("run_shell", "execute_command", "kill_pid")):
                raise RuntimeError(f"adapter flow exposed a generic/raw command action: {plan!r}")

            print("V1.2 QUIETWARD ADAPTER LIVE ACCEPTANCE: PASS")
            print("detector_database_mode=read_only")
            print("events_forwarded=1")
            print("signed_source=quietward")
            print("adapter_credential=event_ingestion_only")
            print("adapter_subkey_action_polling=rejected")
            print("deterministic_checkpoint_replay=no_duplicate_send")
            print("response_incident_created=yes")
            print("high_signal_process_diagnostic=yes")
            print("handle_bound_process_containment=yes")
            print("generic_command_surface=no")
            return 0
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
