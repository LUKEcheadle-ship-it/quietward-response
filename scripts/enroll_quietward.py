#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"


def _env_file_value(name: str) -> str | None:
    if not ENV_FILE.exists():
        return None
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    prefix = name + "="
    for line in reversed(lines):
        if line.startswith(prefix):
            value = line[len(prefix):].strip()
            return value or None
    return None


def _resolve_api_url(explicit: str | None) -> str:
    if explicit:
        return explicit.rstrip("/")
    configured = os.environ.get("NEXT_PUBLIC_API_URL") or _env_file_value("NEXT_PUBLIC_API_URL")
    if configured:
        return configured.rstrip("/")
    port = os.environ.get("QWR_API_PORT") or _env_file_value("QWR_API_PORT") or "8002"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("QWR_API_PORT must be a valid TCP port")
    return f"http://127.0.0.1:{port}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll a QuietWard agent with QuietWard Response")
    parser.add_argument("--api-url", help="Response API URL; defaults to repository .env settings")
    parser.add_argument("--token", help="QWR_ENROLLMENT_TOKEN; defaults to environment or repository .env")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--display-name")
    parser.add_argument("--agent-version", default="0.4.0a2")
    args = parser.parse_args()

    token = args.token or os.environ.get("QWR_ENROLLMENT_TOKEN") or _env_file_value("QWR_ENROLLMENT_TOKEN")
    if not token:
        print("Enrollment token not found. Run scripts/bootstrap_local.sh or set QWR_ENROLLMENT_TOKEN.")
        return 2
    try:
        api_url = _resolve_api_url(args.api_url)
    except ValueError as exc:
        print(str(exc))
        return 2

    payload = json.dumps(
        {
            "host_id": args.host_id,
            "display_name": args.display_name or f"QuietWard on {args.host_id}",
            "agent_version": args.agent_version,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        api_url + "/api/v1/agents/enroll",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-QWR-Enrollment-Token": token,
        },
    )
    try:
        with urlopen(request, timeout=10) as response:
            enrolled = json.loads(response.read())
    except HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"))
        return 1
    except (URLError, OSError) as exc:
        print(f"Enrollment failed: {exc}")
        return 1

    print("Enrollment succeeded. Store the returned secret securely; it is shown only now.\n")
    print("Set these environment variables on the QuietWard endpoint:")
    print("QUIETWARD_RESPONSE_ENABLED=true")
    print(f"QUIETWARD_RESPONSE_URL={api_url}")
    print(f"QUIETWARD_RESPONSE_AGENT_ID={enrolled['agent_id']}")
    print(f"QUIETWARD_RESPONSE_KEY_ID={enrolled['key_id']}")
    print(f"QUIETWARD_RESPONSE_SECRET={enrolled['secret']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
