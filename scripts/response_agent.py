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
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class ResponseAgentError(RuntimeError):
    pass


_ALLOWED_ACTION_FIELDS = {
    "schema_version",
    "action_id",
    "incident_id",
    "target_agent_id",
    "target_host_id",
    "action_type",
    "parameters",
    "requested_at",
    "requested_by",
    "approval_id",
    "expires_at",
    "status",
    "policy_allowed",
    "policy_reasons",
    "dispatched_at",
    "started_at",
    "completed_at",
    "result",
    "error",
    "evidence",
}
_REQUIRED_ACTION_FIELDS = {
    "schema_version",
    "action_id",
    "incident_id",
    "target_agent_id",
    "target_host_id",
    "action_type",
    "parameters",
    "requested_at",
    "requested_by",
    "approval_id",
    "expires_at",
    "status",
    "policy_allowed",
}
_ONLY_ACTION = "restart_quietward_demo_service"
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _canonical_request(method: str, target: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")


def _parse_utc(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ResponseAgentError(f"action {field_name} must be a timezone-aware timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ResponseAgentError(f"action {field_name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ResponseAgentError(f"action {field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
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
        raise ResponseAgentError("plain HTTP Response agent URL is allowed only on loopback; use HTTPS otherwise")
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
        base_url = _validate_base_url(str(self.base_url))
        state_dir = Path(self.state_dir).expanduser()
        if not state_dir.is_absolute():
            raise ResponseAgentError("Response agent state directory must be absolute")
        if not all(str(value).strip() for value in (self.agent_id, self.key_id, self.secret, self.host_id)):
            raise ResponseAgentError("Response agent credentials/configuration are incomplete")
        try:
            timeout = float(self.timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise ResponseAgentError("Response agent timeout must be numeric") from exc
        if not 0.1 <= timeout <= 60:
            raise ResponseAgentError("Response agent timeout must be between 0.1 and 60")
        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "state_dir", state_dir)
        object.__setattr__(self, "timeout_seconds", timeout)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AgentConfig":
        required = {
            "base_url": str(value.get("base_url") or "").strip(),
            "agent_id": str(value.get("agent_id") or "").strip(),
            "key_id": str(value.get("key_id") or "").strip(),
            "secret": str(value.get("secret") or "").strip(),
            "host_id": str(value.get("host_id") or "").strip(),
            "state_dir": str(value.get("state_dir") or "").strip(),
        }
        missing = [name for name, item in required.items() if not item]
        if missing:
            raise ResponseAgentError(
                "Response agent credentials/configuration are incomplete: " + ", ".join(missing)
            )
        return cls(
            base_url=required["base_url"],
            agent_id=required["agent_id"],
            key_id=required["key_id"],
            secret=required["secret"],
            host_id=required["host_id"],
            state_dir=Path(required["state_dir"]).expanduser(),
            timeout_seconds=value.get("timeout_seconds", 5.0),
        )

    @classmethod
    def from_environment(cls) -> "AgentConfig":
        return cls.from_mapping(
            {
                "base_url": os.environ.get("QWR_AGENT_URL", ""),
                "agent_id": os.environ.get("QWR_AGENT_ID", ""),
                "key_id": os.environ.get("QWR_AGENT_KEY_ID", ""),
                "secret": os.environ.get("QWR_AGENT_SECRET", ""),
                "host_id": os.environ.get("QWR_AGENT_HOST_ID", ""),
                "state_dir": os.environ.get("QWR_AGENT_STATE_DIR", ""),
                "timeout_seconds": os.environ.get("QWR_AGENT_TIMEOUT_SECONDS", "5"),
            }
        )

    @classmethod
    def from_file(cls, path: Path) -> "AgentConfig":
        if not path.exists():
            raise ResponseAgentError(f"Response agent config file does not exist: {path}")
        value = _load_json(path, dict)
        return cls.from_mapping(value)

    def to_private_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "secret": self.secret,
            "host_id": self.host_id,
            "state_dir": str(self.state_dir),
            "timeout_seconds": self.timeout_seconds,
        }


def write_agent_config(path: Path, config: AgentConfig, *, force: bool = False) -> Path:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise ResponseAgentError("Response agent config path must be absolute")
    if resolved.exists() and not force:
        raise ResponseAgentError(f"Response agent config already exists: {resolved}")
    _atomic_json(resolved, config.to_private_dict())
    return resolved


class ResponseAgent:
    """Standalone Response-owned alpha agent.

    The alpha agent has exactly one local action: the dedicated demo-fixture reset.
    It has no shell, subprocess, service-manager, process-control, firewall,
    quarantine, account-management, container-control, or package-management API.
    """

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._key = _derive_hmac_key(config.secret)
        self.ledger_path = config.state_dir / "response-agent-ledger.json"
        self.demo_state_path = config.state_dir / "response-agent-demo.json"

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
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_action_id": None,
            "last_action_result": None,
        }
        _atomic_json(self.demo_state_path, state)
        return self.demo_state_path

    def _load_demo_state(self) -> dict[str, Any]:
        state = _load_json(self.demo_state_path, dict)
        if not state:
            raise ResponseAgentError("dedicated Response agent demo fixture is not initialized")
        if state.get("fixture") != "quietward-response-agent-demo":
            raise ResponseAgentError("demo state does not identify the dedicated Response fixture")
        return state

    def _load_ledger(self) -> dict[str, dict[str, Any]]:
        value = _load_json(self.ledger_path, dict)
        if any(not isinstance(item, dict) for item in value.values()):
            raise ResponseAgentError("Response agent ledger has invalid entries")
        return value

    def _save_ledger(self, value: dict[str, dict[str, Any]]) -> None:
        _atomic_json(self.ledger_path, value)

    def _has_local_history(self, action_id: str, ledger: dict[str, dict[str, Any]]) -> bool:
        prior = ledger.get(action_id)
        if prior and prior.get("status") in {"executing", "succeeded", "failed"}:
            return True
        if not self.demo_state_path.exists():
            return False
        state = self._load_demo_state()
        return state.get("last_action_id") == action_id

    def _validate_action(self, action: dict[str, Any], ledger: dict[str, dict[str, Any]]) -> str:
        extra = set(action) - _ALLOWED_ACTION_FIELDS
        if extra:
            raise ResponseAgentError(
                "pending action contains unsupported fields: " + ", ".join(sorted(extra))
            )
        missing = _REQUIRED_ACTION_FIELDS - set(action)
        if missing:
            raise ResponseAgentError(
                "pending action is missing required fields: " + ", ".join(sorted(missing))
            )
        if action.get("schema_version") != "1.0":
            raise ResponseAgentError("action schema version is not supported")
        if action.get("target_agent_id") != self.config.agent_id:
            raise ResponseAgentError("action targets another agent")
        if action.get("target_host_id") != self.config.host_id:
            raise ResponseAgentError("action targets another host")
        if action.get("action_type") != _ONLY_ACTION:
            raise ResponseAgentError("action type is not allowlisted by the Response agent")
        if action.get("parameters") != {}:
            raise ResponseAgentError("demo action accepts no parameters")
        if action.get("policy_allowed") is not True:
            raise ResponseAgentError("action was not policy-allowed by Response")
        status = action.get("status")
        if status not in {"dispatching", "executing"}:
            raise ResponseAgentError("action lifecycle status is not deliverable")

        action_id = action.get("action_id")
        if not isinstance(action_id, str) or not action_id or len(action_id) > 36:
            raise ResponseAgentError("action id is invalid")
        for field_name in ("incident_id", "approval_id", "requested_by"):
            value = action.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise ResponseAgentError(f"action {field_name} is required")

        requested = _parse_utc(action.get("requested_at"), "requested_at")
        expires = _parse_utc(action.get("expires_at"), "expires_at")
        if expires <= requested:
            raise ResponseAgentError("action expiry must be later than request time")
        local_history = self._has_local_history(action_id, ledger)
        if status == "executing" and not local_history:
            raise ResponseAgentError(
                "server returned executing action without matching local execution history"
            )
        if status == "dispatching" and expires <= datetime.now(timezone.utc) and not local_history:
            raise ResponseAgentError("action expired before local execution began")
        return action_id

    def _apply_demo_action(self, action_id: str) -> dict[str, Any]:
        state = self._load_demo_state()
        if state.get("last_action_id") == action_id and isinstance(
            state.get("last_action_result"), dict
        ):
            return dict(state["last_action_result"])
        before = {key: value for key, value in state.items() if key != "last_action_result"}
        state["status"] = "running"
        state["restart_count"] = int(state.get("restart_count", 0)) + 1
        state["last_restarted_at"] = datetime.now(timezone.utc).isoformat()
        state["last_action_id"] = action_id
        after = {key: value for key, value in state.items() if key != "last_action_result"}
        result = {"before": before, "after": after}
        state["last_action_result"] = result
        _atomic_json(self.demo_state_path, state)
        return result

    def _post_result(
        self,
        action_id: str,
        status: str,
        result: dict[str, Any],
        error: str | None = None,
    ) -> Any:
        now = datetime.now(timezone.utc).isoformat()
        return self._request(
            "POST",
            f"/api/v1/actions/{action_id}/result",
            {
                "schema_version": "1.0",
                "action_id": action_id,
                "agent_id": self.config.agent_id,
                "host_id": self.config.host_id,
                "status": status,
                "started_at": now,
                "completed_at": now if status in {"succeeded", "failed"} else None,
                "result": result,
                "error": error,
                "evidence": {"executor": "quietward-response-agent-alpha1-demo"},
                "agent_version": "1.1.0-alpha.1",
            },
        )

    def poll_once(self) -> int:
        target = f"/api/v1/agents/{self.config.agent_id}/actions/pending"
        actions = self._request("GET", target)
        if not isinstance(actions, list):
            raise ResponseAgentError("pending action response is not a list")
        ledger = self._load_ledger()
        executed = 0

        for action in actions:
            if not isinstance(action, dict):
                raise ResponseAgentError("pending action response contains a non-object item")
            action_id = self._validate_action(action, ledger)
            prior = ledger.get(action_id)
            if prior and prior.get("status") in {"succeeded", "failed"}:
                self._post_result(
                    action_id,
                    str(prior["status"]),
                    dict(prior.get("result") or {}),
                    prior.get("error"),
                )
                continue

            ledger[action_id] = {"status": "executing", "result": {}, "error": None}
            self._save_ledger(ledger)
            # If the server revoked/cancelled this dispatch after it was returned by
            # polling, this acknowledgement fails and local mutation never begins.
            self._post_result(action_id, "executing", {})

            state_before = self._load_demo_state()
            already_applied = state_before.get("last_action_id") == action_id
            try:
                result = self._apply_demo_action(action_id)
                final = {"status": "succeeded", "result": result, "error": None}
            except Exception as exc:
                final = {"status": "failed", "result": {}, "error": str(exc)[:1000]}
            ledger[action_id] = final
            self._save_ledger(ledger)
            self._post_result(
                action_id,
                str(final["status"]),
                dict(final["result"]),
                final["error"],
            )
            if final["status"] == "succeeded" and not already_applied:
                executed += 1
        return executed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Standalone QuietWard Response alpha agent (demo action only)."
    )
    parser.add_argument(
        "command",
        choices=("init-demo-unhealthy", "init-demo-running", "status", "poll-once"),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Private JSON configuration written by enroll_response_agent.py. Environment variables are used when omitted.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    config = AgentConfig.from_file(args.config.expanduser()) if args.config else AgentConfig.from_environment()
    agent = ResponseAgent(config)
    if args.command == "init-demo-unhealthy":
        path = agent.initialize_demo_fixture(unhealthy=True)
        print(path)
        return 0
    if args.command == "init-demo-running":
        path = agent.initialize_demo_fixture(unhealthy=False)
        print(path)
        return 0
    if args.command == "status":
        state = agent._load_demo_state()
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    executed = agent.poll_once()
    print(json.dumps({"actions_executed": executed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
