#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from manage_audit_checkpoint import CheckpointToolError, _load_checkpoint


EXPECTED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "terminate_process_by_handle",
    "collect_file_diagnostic",
    "quarantine_artifact_by_handle",
    "restore_quarantined_artifact_by_handle",
}
FORBIDDEN_ACTION_FRAGMENTS = (
    "shell",
    "command",
    "powershell",
    "script",
    "arbitrary",
)
CAPABILITY_MAX_AGE = timedelta(minutes=15)
FUTURE_SKEW = timedelta(seconds=30)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class DiagnoseError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str


def _base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DiagnoseError("API URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise DiagnoseError("API URL must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise DiagnoseError("API URL must not contain a path, query, or fragment")
    host = parsed.hostname.lower()
    loopback = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise DiagnoseError("plain HTTP is allowed only for loopback Response; use HTTPS otherwise")
    return normalized


def _token(explicit: str | None) -> str:
    value = str(explicit or os.environ.get("QWR_ANALYST_TOKEN") or "").strip()
    if not value:
        value = getpass.getpass("Response analyst bearer token: ").strip()
    if not value:
        raise DiagnoseError("analyst bearer token is required")
    if len(value) > 512:
        raise DiagnoseError("analyst bearer token is unexpectedly long")
    return value


def _request(
    base_url: str,
    token: str | None,
    target: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> Any:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if payload is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(base_url + target, data=body, method=method, headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise DiagnoseError(f"HTTP {exc.code} for {target}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise DiagnoseError(f"Response API unavailable: {exc}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise DiagnoseError(f"Response payload too large for diagnostic: {target}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiagnoseError(f"Response returned invalid JSON: {target}") from exc


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def run_checks(base_url: str, token: str, *, checkpoint_file: Path | None = None) -> list[Check]:
    checks: list[Check] = []

    health = _request(base_url, None, "/health")
    if isinstance(health, dict):
        checks.append(Check("health", "PASS", "health endpoint reachable"))
    else:
        checks.append(Check("health", "FAIL", "health endpoint returned invalid data"))

    registry = _request(base_url, token, "/api/v1/actions/registry")
    if not isinstance(registry, list):
        checks.append(Check("action_registry", "FAIL", "registry response is not a list"))
    else:
        action_types = {
            str(item.get("action_type") or "")
            for item in registry
            if isinstance(item, dict)
        }
        if action_types != EXPECTED_ACTIONS:
            checks.append(
                Check(
                    "action_registry",
                    "FAIL",
                    f"unexpected action surface ({len(action_types)} action types)",
                )
            )
        elif any(
            fragment in action.casefold()
            for action in action_types
            for fragment in FORBIDDEN_ACTION_FRAGMENTS
        ):
            checks.append(Check("action_registry", "FAIL", "generic execution action detected"))
        elif any(
            not isinstance(item, dict) or item.get("approval_required") is not True
            for item in registry
        ):
            checks.append(Check("action_registry", "FAIL", "an action bypasses approval"))
        else:
            checks.append(Check("action_registry", "PASS", "exact seven-action approved surface"))

    audit = _request(base_url, token, "/api/v1/audit/verify")
    if isinstance(audit, dict) and audit.get("valid") is True:
        checks.append(
            Check(
                "audit_chain",
                "PASS",
                f"valid; entries={int(audit.get('entries_checked', 0))}",
            )
        )
    else:
        checks.append(Check("audit_chain", "FAIL", "audit chain verification failed"))

    agents = _request(base_url, token, "/api/v1/agents")
    now = datetime.now(timezone.utc)
    if not isinstance(agents, list):
        checks.append(Check("agent_capabilities", "FAIL", "agents response is not a list"))
    else:
        enabled = [item for item in agents if isinstance(item, dict) and item.get("enabled") is True]
        stale: list[str] = []
        missing: list[str] = []
        future: list[str] = []
        for item in enabled:
            agent_id = str(item.get("agent_id") or "unknown")[:64]
            updated = _parse_time(item.get("capabilities_updated_at"))
            if updated is None:
                missing.append(agent_id)
            elif updated > now + FUTURE_SKEW:
                future.append(agent_id)
            elif updated < now - CAPABILITY_MAX_AGE:
                stale.append(agent_id)
        if future:
            checks.append(
                Check(
                    "agent_capabilities",
                    "FAIL",
                    f"{len(future)} enabled agent(s) report future capability timestamps",
                )
            )
        elif stale or missing:
            checks.append(
                Check(
                    "agent_capabilities",
                    "WARN",
                    f"enabled agents stale={len(stale)} never_reported={len(missing)}",
                )
            )
        else:
            checks.append(
                Check(
                    "agent_capabilities",
                    "PASS",
                    f"{len(enabled)} enabled agent(s) have fresh signed capability state",
                )
            )

    if checkpoint_file is not None:
        try:
            checkpoint = _load_checkpoint(checkpoint_file)
            result = _request(
                base_url,
                token,
                "/api/v1/audit/checkpoint/verify",
                method="POST",
                payload=checkpoint,
            )
        except (CheckpointToolError, DiagnoseError) as exc:
            checks.append(Check("retained_checkpoint", "FAIL", str(exc)))
        else:
            if isinstance(result, dict) and result.get("valid") is True:
                checks.append(
                    Check(
                        "retained_checkpoint",
                        "PASS",
                        f"anchored entries={result.get('entries_checked')}",
                    )
                )
            else:
                checks.append(
                    Check(
                        "retained_checkpoint",
                        "FAIL",
                        "retained checkpoint does not verify",
                    )
                )

    return checks


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run read-only security diagnostics against a QuietWard Response API."
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8002")
    parser.add_argument(
        "--token",
        help="Analyst bearer token. Prefer QWR_ANALYST_TOKEN or prompt to avoid process-list exposure.",
    )
    parser.add_argument(
        "--checkpoint-file",
        type=Path,
        help="Optional absolute retained signed audit checkpoint to verify.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat WARN results (for example a stale enabled agent) as failure.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    base_url = _base_url(args.api_url)
    token = _token(args.token)
    checkpoint = args.checkpoint_file.expanduser() if args.checkpoint_file else None
    if checkpoint is not None and not checkpoint.is_absolute():
        raise SystemExit("--checkpoint-file must be absolute")

    checks = run_checks(base_url, token, checkpoint_file=checkpoint)
    print("QUIETWARD RESPONSE SECURITY DIAGNOSTIC")
    for item in checks:
        print(f"{item.status:4} {item.name}: {item.detail}")
    print("The analyst bearer token was not printed.")

    if any(item.status == "FAIL" for item in checks):
        return 1
    if args.strict and any(item.status == "WARN" for item in checks):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
