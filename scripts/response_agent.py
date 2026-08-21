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

from response_agent_resources import (
    ResourceError,
    ResourceHandleStore,
    collect_file_diagnostic,
    collect_host_diagnostic,
    collect_process_diagnostic,
    quarantine_file_by_handle,
    restore_quarantined_file,
    terminate_process_by_handle,
)


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
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

_ACTION_PARAMETER_MODE = {
    "restart_quietward_demo_service": "none",
    "collect_host_diagnostic": "none",
    "collect_process_diagnostic": "none",
    "terminate_process_by_handle": "resource_handle",
    "collect_file_diagnostic": "none",
    "quarantine_artifact_by_handle": "resource_handle",
    "restore_quarantined_artifact_by_handle": "resource_handle",
}
_MUTATING_ACTIONS = {
    "restart_quietward_demo_service",
    "terminate_process_by_handle",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
}


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


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _paths(value: Any) -> tuple[Path, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw = [item for item in value.split(os.pathsep) if item.strip()]
    elif isinstance(value, (list, tuple)):
        raw = list(value)
    else:
        raise ResponseAgentError("managed_roots must be a list or path-separated string")
    result: list[Path] = []
    for item in raw:
        path = Path(str(item)).expanduser()
        if not path.is_absolute():
            raise ResponseAgentError("every managed root must be absolute")
        result.append(path)
    return tuple(result)


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class AgentConfig:
    base_url: str
    agent_id: str
    key_id: str
    secret: str
    host_id: str
    state_dir: Path
    timeout_seconds: float = 5.0
    managed_roots: tuple[Path, ...] = ()
    quarantine_dir: Path | None = None
    enable_process_termination: bool = False
    enable_file_quarantine: bool = False

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

        roots = tuple(Path(item).expanduser() for item in self.managed_roots)
        if any(not item.is_absolute() for item in roots):
            raise ResponseAgentError("every managed root must be absolute")
        quarantine = Path(self.quarantine_dir).expanduser() if self.quarantine_dir else state_dir / "quarantine"
        if not quarantine.is_absolute():
            raise ResponseAgentError("Response quarantine directory must be absolute")
        normalized_quarantine = quarantine.resolve()
        for root in roots:
            normalized_root = root.resolve()
            if _path_within(normalized_quarantine, normalized_root):
                raise ResponseAgentError("quarantine directory must not be inside a managed root")

        object.__setattr__(self, "base_url", base_url)
        object.__setattr__(self, "state_dir", state_dir)
        object.__setattr__(self, "timeout_seconds", timeout)
        object.__setattr__(self, "managed_roots", roots)
        object.__setattr__(self, "quarantine_dir", quarantine)
        object.__setattr__(self, "enable_process_termination", bool(self.enable_process_termination))
        object.__setattr__(self, "enable_file_quarantine", bool(self.enable_file_quarantine))

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
        quarantine_raw = value.get("quarantine_dir")
        quarantine = Path(str(quarantine_raw)).expanduser() if quarantine_raw else None
        return cls(
            base_url=required["base_url"],
            agent_id=required["agent_id"],
            key_id=required["key_id"],
            secret=required["secret"],
            host_id=required["host_id"],
            state_dir=Path(required["state_dir"]).expanduser(),
            timeout_seconds=value.get("timeout_seconds", 5.0),
            managed_roots=_paths(value.get("managed_roots")),
            quarantine_dir=quarantine,
            enable_process_termination=_truthy(value.get("enable_process_termination")),
            enable_file_quarantine=_truthy(value.get("enable_file_quarantine")),
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
                "managed_roots": os.environ.get("QWR_AGENT_MANAGED_ROOTS", ""),
                "quarantine_dir": os.environ.get("QWR_AGENT_QUARANTINE_DIR", ""),
                "enable_process_termination": os.environ.get("QWR_AGENT_ENABLE_PROCESS_TERMINATION", "0"),
                "enable_file_quarantine": os.environ.get("QWR_AGENT_ENABLE_FILE_QUARANTINE", "0"),
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
            "managed_roots": [str(item) for item in self.managed_roots],
            "quarantine_dir": str(self.quarantine_dir),
            "enable_process_termination": self.enable_process_termination,
            "enable_file_quarantine": self.enable_file_quarantine,
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
    """Response-owned outward-polling agent with narrow typed local executors."""

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._key = _derive_hmac_key(config.secret)
        self.ledger_path = config.state_dir / "response-agent-ledger.json"
        self.demo_state_path = config.state_dir / "response-agent-demo.json"
        self.resources = ResourceHandleStore(config.state_dir)

    def capabilities(self) -> dict[str, Any]:
        return {
            "read_only_actions": [
                "collect_host_diagnostic",
                "collect_process_diagnostic",
                "collect_file_diagnostic",
            ],
            "mutating_actions": {
                "restart_quietward_demo_service": True,
                "terminate_process_by_handle": self.config.enable_process_termination,
                "quarantine_artifact_by_handle": self.config.enable_file_quarantine,
                "restore_quarantined_artifact_by_handle": self.config.enable_file_quarantine,
            },
            "managed_roots": [str(item) for item in self.config.managed_roots],
            "quarantine_dir": str(self.config.quarantine_dir),
            "arbitrary_command_execution": False,
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
        if self.demo_state_path.exists():
            try:
                return self._load_demo_state().get("last_action_id") == action_id
            except ResponseAgentError:
                return False
        return False

    def _validate_parameters(self, action_type: str, parameters: Any) -> None:
        if not isinstance(parameters, dict):
            raise ResponseAgentError("action parameters must be an object")
        mode = _ACTION_PARAMETER_MODE[action_type]
        if mode == "none":
            if parameters:
                raise ResponseAgentError("action accepts no parameters")
            return
        if set(parameters) != {"resource_handle"}:
            raise ResponseAgentError("action requires exactly one resource_handle parameter")
        handle = parameters.get("resource_handle")
        if not isinstance(handle, str) or not handle.startswith("qwrh1_") or len(handle) > 96:
            raise ResponseAgentError("resource_handle format is invalid")

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
        action_type = action.get("action_type")
        if action_type not in _ACTION_PARAMETER_MODE:
            raise ResponseAgentError("action type is not allowlisted by the Response agent")
        self._validate_parameters(str(action_type), action.get("parameters"))
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

    def _execute_action(self, action: dict[str, Any], *, recover_after_started: bool) -> dict[str, Any]:
        action_type = str(action["action_type"])
        parameters = dict(action.get("parameters") or {})
        handle = str(parameters.get("resource_handle") or "")
        try:
            if action_type == "restart_quietward_demo_service":
                return self._apply_demo_action(str(action["action_id"]))
            if action_type == "collect_host_diagnostic":
                return collect_host_diagnostic(self.config.state_dir)
            if action_type == "collect_process_diagnostic":
                return collect_process_diagnostic(self.resources)
            if action_type == "terminate_process_by_handle":
                if not self.config.enable_process_termination:
                    raise ResponseAgentError("process termination capability is disabled in agent config")
                return terminate_process_by_handle(
                    self.resources,
                    handle,
                    recover_after_started=recover_after_started,
                )
            if action_type == "collect_file_diagnostic":
                return collect_file_diagnostic(self.resources, self.config.managed_roots)
            if action_type == "quarantine_artifact_by_handle":
                if not self.config.enable_file_quarantine:
                    raise ResponseAgentError("file quarantine capability is disabled in agent config")
                if not self.config.managed_roots:
                    raise ResponseAgentError("file quarantine requires at least one managed root")
                return quarantine_file_by_handle(
                    self.resources,
                    handle,
                    Path(self.config.quarantine_dir),
                    recover_after_started=recover_after_started,
                )
            if action_type == "restore_quarantined_artifact_by_handle":
                if not self.config.enable_file_quarantine:
                    raise ResponseAgentError("file quarantine/restore capability is disabled in agent config")
                return restore_quarantined_file(
                    self.resources,
                    handle,
                    recover_after_started=recover_after_started,
                )
        except ResourceError as exc:
            raise ResponseAgentError(str(exc)) from exc
        raise ResponseAgentError("action type has no local executor")

    def _post_result(
        self,
        action_id: str,
        status: str,
        result: dict[str, Any],
        error: str | None = None,
        *,
        action_type: str,
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
                "evidence": {
                    "executor": "quietward-response-agent-v1.2",
                    "action_type": action_type,
                },
                "agent_version": "1.2.0-alpha.1",
            },
        )

    def poll_once(self) -> int:
        target = f"/api/v1/agents/{self.config.agent_id}/actions/pending"
        actions = self._request("GET", target)
        if not isinstance(actions, list):
            raise ResponseAgentError("pending action response is not a list")
        ledger = self._load_ledger()
        completed = 0

        for action in actions:
            if not isinstance(action, dict):
                raise ResponseAgentError("pending action response contains a non-object item")
            action_id = self._validate_action(action, ledger)
            action_type = str(action["action_type"])
            prior = ledger.get(action_id)
            if prior and prior.get("status") in {"succeeded", "failed"}:
                self._post_result(
                    action_id,
                    str(prior["status"]),
                    dict(prior.get("result") or {}),
                    prior.get("error"),
                    action_type=action_type,
                )
                continue

            recovering = bool(prior and prior.get("status") == "executing")
            if not recovering:
                ledger[action_id] = {
                    "status": "executing",
                    "action_type": action_type,
                    "parameters": dict(action.get("parameters") or {}),
                    "mutation_started": False,
                    "result": {},
                    "error": None,
                }
                self._save_ledger(ledger)
                self._post_result(action_id, "executing", {}, action_type=action_type)

            if action_type in _MUTATING_ACTIONS and not ledger[action_id].get("mutation_started"):
                ledger[action_id]["mutation_started"] = True
                self._save_ledger(ledger)

            try:
                result = self._execute_action(
                    action,
                    recover_after_started=bool(ledger[action_id].get("mutation_started") and recovering),
                )
                final = {"status": "succeeded", "result": result, "error": None}
            except Exception as exc:
                final = {"status": "failed", "result": {}, "error": str(exc)[:1000]}
            ledger[action_id].update(final)
            self._save_ledger(ledger)
            self._post_result(
                action_id,
                str(final["status"]),
                dict(final["result"]),
                final["error"],
                action_type=action_type,
            )
            if final["status"] == "succeeded" and not recovering:
                completed += 1
        return completed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="QuietWard Response v1.2 alpha agent with bounded typed actions."
    )
    parser.add_argument(
        "command",
        choices=(
            "init-demo-unhealthy",
            "init-demo-running",
            "status",
            "capabilities",
            "poll-once",
        ),
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
    if args.command == "capabilities":
        print(json.dumps(agent.capabilities(), indent=2, sort_keys=True))
        return 0
    completed = agent.poll_once()
    print(json.dumps({"actions_completed": completed}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
