#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from response_agent_diagnostics import (
    DiagnosticError,
    collect_host_diagnostic,
    collect_network_diagnostic,
    collect_process_diagnostic,
)


class ResponseAgentError(RuntimeError):
    pass


_ALLOWED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
}
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def _utc_text() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_utc(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ResponseAgentError(f"action {field_name} must be a timezone-aware timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ResponseAgentError(f"action {field_name} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResponseAgentError(f"action {field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short Response agent state write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _load_json(path: Path, expected_type: type) -> Any:
    if not path.exists():
        return expected_type()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResponseAgentError(f"agent state is unreadable or invalid: {path.name}") from exc
    if not isinstance(value, expected_type):
        raise ResponseAgentError(f"agent state has invalid structure: {path.name}")
    return value


def _validate_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ResponseAgentError("Response agent URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ResponseAgentError("Response agent URL must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ResponseAgentError("Response agent URL must not contain a path, query, or fragment")
    hostname = parsed.hostname.lower()
    loopback = hostname in _LOOPBACK_HOSTS or hostname.endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise ResponseAgentError("plain HTTP is allowed only on loopback; use HTTPS otherwise")
    return normalized


@dataclass(frozen=True, slots=True)
class AgentConfig:
    base_url: str
    agent_id: str
    key_id: str
    secret: str
    host_id: str
    state_dir: Path
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not all(str(value).strip() for value in (self.agent_id, self.key_id, self.secret, self.host_id)):
            raise ResponseAgentError("Response agent credentials are incomplete")
        state_dir = Path(self.state_dir).expanduser()
        if not state_dir.is_absolute():
            raise ResponseAgentError("Response agent state directory must be absolute")
        timeout = float(self.timeout_seconds)
        if not 0.1 <= timeout <= 60:
            raise ResponseAgentError("Response agent timeout must be between 0.1 and 60 seconds")
        object.__setattr__(self, "base_url", _validate_base_url(self.base_url))
        object.__setattr__(self, "state_dir", state_dir)
        object.__setattr__(self, "timeout_seconds", timeout)

    @classmethod
    def from_file(cls, path: Path) -> "AgentConfig":
        resolved = path.expanduser().resolve()
        if not resolved.is_file():
            raise ResponseAgentError(f"Response agent config file does not exist: {resolved}")
        if os.name != "nt":
            mode = stat.S_IMODE(resolved.stat().st_mode)
            if mode & 0o077:
                raise ResponseAgentError("Response agent config must not be group/world accessible")
        value = _load_json(resolved, dict)
        try:
            return cls(
                base_url=str(value["base_url"]),
                agent_id=str(value["agent_id"]),
                key_id=str(value["key_id"]),
                secret=str(value["secret"]),
                host_id=str(value["host_id"]),
                state_dir=Path(str(value["state_dir"])),
                timeout_seconds=float(value.get("timeout_seconds", 5.0)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResponseAgentError("Response agent config is incomplete") from exc


class ResponseAgent:
    """Response-owned outward-polling executor for a finite diagnostic allowlist."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._key = _derive_hmac_key(config.secret)
        self._network_privacy_key = hmac.new(
            self._key,
            b"quietward-response-network-diagnostic-v1",
            hashlib.sha256,
        ).digest()
        self.ledger_path = config.state_dir / "response-agent-ledger.json"
        self.demo_state_path = config.state_dir / "response-agent-demo.json"

    def capabilities(self) -> dict[str, Any]:
        return {
            "read_only_actions": [
                "collect_host_diagnostic",
                "collect_process_diagnostic",
                "collect_network_diagnostic",
            ],
            "mutating_actions": ["restart_quietward_demo_service"],
            "arbitrary_command_execution": False,
            "raw_process_command_lines": False,
            "raw_executable_paths": False,
            "raw_remote_network_addresses": False,
        }

    def _signed_headers(self, method: str, target: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        signature = hmac.new(
            self._key,
            _canonical_request(method, target, timestamp, nonce, body),
            hashlib.sha256,
        ).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-QWR-Agent-ID": self.config.agent_id,
            "X-QWR-Key-ID": self.config.key_id,
            "X-QWR-Timestamp": timestamp,
            "X-QWR-Nonce": nonce,
            "X-QWR-Signature": signature,
        }

    def _request(self, method: str, target: str, payload: dict[str, Any] | None = None) -> Any:
        body = b"" if payload is None else json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        request = Request(
            self.config.base_url + target,
            data=None if method.upper() == "GET" else body,
            method=method.upper(),
            headers=self._signed_headers(method, target, body),
        )
        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:1000]
            raise ResponseAgentError(
                f"Response API HTTP {exc.code} for {method.upper()} {target}: {detail}"
            ) from exc
        except (URLError, OSError) as exc:
            raise ResponseAgentError(f"Response API unavailable: {exc}") from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ResponseAgentError("Response API returned invalid JSON") from exc

    def initialize_demo_fixture(self, *, unhealthy: bool = True) -> Path:
        state = {
            "fixture": "quietward-response-agent-demo",
            "status": "unhealthy" if unhealthy else "running",
            "restart_count": 0,
            "created_at": _utc_text(),
            "last_action_id": None,
            "last_action_result": None,
        }
        _atomic_json(self.demo_state_path, state)
        return self.demo_state_path

    def _load_ledger(self) -> dict[str, dict[str, Any]]:
        value = _load_json(self.ledger_path, dict)
        if any(not isinstance(item, dict) for item in value.values()):
            raise ResponseAgentError("Response agent ledger has invalid entries")
        return value

    def _save_ledger(self, value: dict[str, dict[str, Any]]) -> None:
        if len(value) > 4096:
            ordered = list(value.items())[-4096:]
            value = dict(ordered)
        _atomic_json(self.ledger_path, value)

    def _validate_action(self, action: dict[str, Any], ledger: dict[str, dict[str, Any]]) -> str:
        required = {
            "schema_version",
            "action_id",
            "incident_id",
            "target_agent_id",
            "target_host_id",
            "action_type",
            "parameters",
            "requested_at",
            "approval_id",
            "expires_at",
            "status",
            "policy_allowed",
        }
        missing = required - set(action)
        if missing:
            raise ResponseAgentError("pending action is missing required fields")
        if action.get("schema_version") != "1.0":
            raise ResponseAgentError("action schema version is not supported")
        if action.get("target_agent_id") != self.config.agent_id:
            raise ResponseAgentError("action targets another agent")
        if action.get("target_host_id") != self.config.host_id:
            raise ResponseAgentError("action targets another host")
        action_type = str(action.get("action_type") or "")
        if action_type not in _ALLOWED_ACTIONS:
            raise ResponseAgentError("action type is not allowlisted by the Response agent")
        if action.get("parameters") != {}:
            raise ResponseAgentError("diagnostic action accepts no parameters")
        if action.get("policy_allowed") is not True:
            raise ResponseAgentError("action was not policy-allowed by Response")
        if not str(action.get("approval_id") or "").strip():
            raise ResponseAgentError("action does not carry an analyst approval binding")
        status = str(action.get("status") or "")
        if status not in {"dispatching", "executing"}:
            raise ResponseAgentError("action lifecycle status is not deliverable")
        action_id = str(action.get("action_id") or "")
        if not action_id or len(action_id) > 36:
            raise ResponseAgentError("action id is invalid")
        requested = _parse_utc(action.get("requested_at"), "requested_at")
        expires = _parse_utc(action.get("expires_at"), "expires_at")
        if expires <= requested:
            raise ResponseAgentError("action expiry must be later than request time")
        prior = ledger.get(action_id)
        if status == "executing" and prior is None:
            raise ResponseAgentError("server returned executing action without local execution history")
        if status == "dispatching" and expires <= datetime.now(timezone.utc) and prior is None:
            raise ResponseAgentError("action expired before local execution began")
        return action_id

    def _apply_demo_action(self, action_id: str) -> dict[str, Any]:
        state = _load_json(self.demo_state_path, dict)
        if state.get("fixture") != "quietward-response-agent-demo":
            raise ResponseAgentError("dedicated Response demo fixture is not initialized")
        if state.get("last_action_id") == action_id and isinstance(state.get("last_action_result"), dict):
            return dict(state["last_action_result"])
        before = {key: value for key, value in state.items() if key != "last_action_result"}
        state["status"] = "running"
        state["restart_count"] = int(state.get("restart_count", 0)) + 1
        state["last_restarted_at"] = _utc_text()
        state["last_action_id"] = action_id
        after = {key: value for key, value in state.items() if key != "last_action_result"}
        result = {"before": before, "after": after}
        state["last_action_result"] = result
        _atomic_json(self.demo_state_path, state)
        return result

    def _execute(self, action: dict[str, Any]) -> dict[str, Any]:
        action_type = str(action["action_type"])
        try:
            if action_type == "restart_quietward_demo_service":
                return self._apply_demo_action(str(action["action_id"]))
            if action_type == "collect_host_diagnostic":
                return collect_host_diagnostic(self.config.state_dir)
            if action_type == "collect_process_diagnostic":
                return collect_process_diagnostic()
            if action_type == "collect_network_diagnostic":
                return collect_network_diagnostic(self._network_privacy_key)
        except DiagnosticError as exc:
            raise ResponseAgentError(str(exc)) from exc
        raise ResponseAgentError("action type has no local executor")

    def _post_result(
        self,
        *,
        action_id: str,
        action_type: str,
        status: str,
        started_at: str,
        result: dict[str, Any],
        error: str | None = None,
    ) -> Any:
        return self._request(
            "POST",
            f"/api/v1/actions/{action_id}/result",
            {
                "schema_version": "1.0",
                "action_id": action_id,
                "agent_id": self.config.agent_id,
                "host_id": self.config.host_id,
                "status": status,
                "started_at": started_at,
                "completed_at": _utc_text() if status in {"succeeded", "failed"} else None,
                "result": result,
                "error": error,
                "evidence": {
                    "executor": "quietward-response-diagnostic-agent",
                    "action_type": action_type,
                    "read_only_diagnostic": action_type.startswith("collect_"),
                },
                "agent_version": "1.1.0-alpha.1",
            },
        )

    def poll_once(self) -> int:
        target = f"/api/v1/agents/{self.config.agent_id}/actions/pending"
        actions = self._request("GET", target)
        if not isinstance(actions, list):
            raise ResponseAgentError("pending action response is not a list")
        ledger = self._load_ledger()
        completed = 0

        for raw in actions:
            if not isinstance(raw, dict):
                raise ResponseAgentError("pending action response contains a non-object item")
            action_id = self._validate_action(raw, ledger)
            action_type = str(raw["action_type"])
            prior = ledger.get(action_id)

            if prior and prior.get("status") in {"succeeded", "failed"}:
                self._post_result(
                    action_id=action_id,
                    action_type=action_type,
                    status=str(prior["status"]),
                    started_at=str(prior["started_at"]),
                    result=dict(prior.get("result") or {}),
                    error=prior.get("error"),
                )
                continue

            started_at = str(prior.get("started_at")) if prior else _utc_text()
            if prior is None:
                ledger[action_id] = {
                    "status": "executing",
                    "action_type": action_type,
                    "started_at": started_at,
                    "result": {},
                    "error": None,
                }
                self._save_ledger(ledger)
                self._post_result(
                    action_id=action_id,
                    action_type=action_type,
                    status="executing",
                    started_at=started_at,
                    result={},
                )

            try:
                result = self._execute(raw)
                status = "succeeded"
                error = None
            except Exception as exc:
                result = {}
                status = "failed"
                error = str(exc)[:4096]

            ledger[action_id] = {
                "status": status,
                "action_type": action_type,
                "started_at": started_at,
                "result": result,
                "error": error,
            }
            self._save_ledger(ledger)
            self._post_result(
                action_id=action_id,
                action_type=action_type,
                status=status,
                started_at=started_at,
                result=result,
                error=error,
            )
            completed += 1
        return completed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the QuietWard Response diagnostic agent")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", help="Poll once and exit")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--show-capabilities", action="store_true")
    parser.add_argument("--init-demo", action="store_true")
    args = parser.parse_args()

    if args.interval < 1 or args.interval > 300:
        raise ResponseAgentError("poll interval must be between 1 and 300 seconds")
    agent = ResponseAgent(AgentConfig.from_file(args.config))
    if args.show_capabilities:
        print(json.dumps(agent.capabilities(), indent=2, sort_keys=True))
        return 0
    if args.init_demo:
        print(agent.initialize_demo_fixture())
        if args.once:
            return 0
    while True:
        agent.poll_once()
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ResponseAgentError as exc:
        print(f"Response agent failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
