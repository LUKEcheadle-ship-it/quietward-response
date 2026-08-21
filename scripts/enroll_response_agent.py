#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from response_agent import AgentConfig, ResponseAgentError, write_agent_config


def _default_state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return (base / "QuietWardResponse" / "agent-state").resolve()
    xdg = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return (base / "quietward-response-agent").resolve()


def _default_config_file() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return (base / "QuietWardResponse" / "agent.json").resolve()
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return (base / "quietward-response" / "agent.json").resolve()


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise ResponseAgentError(f"agent enrollment HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise ResponseAgentError(f"Response API unavailable during enrollment: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ResponseAgentError("agent enrollment returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ResponseAgentError("agent enrollment returned an invalid object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Enroll the QuietWard Response v1.2 alpha agent and write a private local config file."
    )
    parser.add_argument("--api-url", default="http://127.0.0.1:8002")
    parser.add_argument(
        "--token",
        default=os.environ.get("QWR_ENROLLMENT_TOKEN"),
        help="Response enrollment token. Defaults to QWR_ENROLLMENT_TOKEN.",
    )
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--display-name")
    parser.add_argument("--state-dir", type=Path, default=_default_state_dir())
    parser.add_argument("--config-file", type=Path, default=_default_config_file())
    parser.add_argument(
        "--managed-root",
        action="append",
        type=Path,
        default=[],
        help="Absolute directory whose regular files may receive opaque diagnostic/quarantine handles. Repeatable.",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        help="Private quarantine directory. Defaults under the agent state directory.",
    )
    parser.add_argument(
        "--enable-process-termination",
        action="store_true",
        help="Opt in to handle-bound exact-process termination.",
    )
    parser.add_argument(
        "--enable-file-quarantine",
        action="store_true",
        help="Opt in to managed-root handle-bound quarantine/restore.",
    )
    parser.add_argument("--force", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    token = str(args.token or "").strip()
    if not token:
        raise SystemExit("--token or QWR_ENROLLMENT_TOKEN is required")
    state_dir = args.state_dir.expanduser().resolve()
    config_file = args.config_file.expanduser().resolve()
    managed_roots = tuple(path.expanduser().resolve() for path in args.managed_root)
    quarantine_dir = (
        args.quarantine_dir.expanduser().resolve()
        if args.quarantine_dir
        else (state_dir / "quarantine").resolve()
    )
    if args.enable_file_quarantine and not managed_roots:
        raise SystemExit("--enable-file-quarantine requires at least one --managed-root")
    display_name = args.display_name or f"Response agent on {args.host_id}"

    value = _post_json(
        args.api_url.rstrip("/") + "/api/v1/agents/enroll",
        {
            "host_id": args.host_id,
            "display_name": display_name,
            "agent_version": "1.2.0-alpha.1",
        },
        {"X-QWR-Enrollment-Token": token},
    )
    required = ("agent_id", "key_id", "secret", "host_id")
    if any(not value.get(key) for key in required):
        raise ResponseAgentError("agent enrollment response is missing required credentials")

    config = AgentConfig(
        base_url=args.api_url.rstrip("/"),
        agent_id=str(value["agent_id"]),
        key_id=str(value["key_id"]),
        secret=str(value["secret"]),
        host_id=str(value["host_id"]),
        state_dir=state_dir,
        managed_roots=managed_roots,
        quarantine_dir=quarantine_dir,
        enable_process_termination=args.enable_process_termination,
        enable_file_quarantine=args.enable_file_quarantine,
    )
    written = write_agent_config(config_file, config, force=args.force)

    print(f"Response agent enrolled: {config.agent_id}")
    print(f"Host: {config.host_id}")
    print(f"Private config: {written}")
    print(f"State directory: {config.state_dir}")
    print(f"Managed roots: {len(config.managed_roots)}")
    print(f"Process termination enabled: {config.enable_process_termination}")
    print(f"File quarantine enabled: {config.enable_file_quarantine}")
    print("The enrollment secret was written to the private config and was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
