#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
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
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith(prefix):
            value = stripped[len(prefix):].strip()
            return value or None
    return None


def _validated_api_url(value: str) -> str:
    resolved = value.strip().rstrip("/")
    parsed = urlparse(resolved)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Response API URL must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Response API URL must not contain credentials, query parameters, or a fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("Response API URL must not include an API path")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Response API URL contains an invalid port") from exc
    return resolved


def _resolve_port() -> int:
    text = os.environ.get("QWR_API_PORT") or _env_file_value("QWR_API_PORT") or "8002"
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValueError("QWR_API_PORT must be a valid TCP port")
    return int(text)


def _resolve_api_url(explicit: str | None) -> str:
    if explicit:
        return _validated_api_url(explicit)

    explicit_environment = os.environ.get("NEXT_PUBLIC_API_URL", "").strip()
    if explicit_environment:
        return _validated_api_url(explicit_environment)

    port = _resolve_port()
    configured = (_env_file_value("NEXT_PUBLIC_API_URL") or "").strip()
    # Keep enrollment aligned with the public bootstrap: if only QWR_API_PORT was
    # changed from the example defaults, do not silently keep calling port 8002.
    if port != 8002 and configured.rstrip("/") in {
        "http://localhost:8002",
        "http://127.0.0.1:8002",
    }:
        configured = ""
    if configured:
        return _validated_api_url(configured)
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
        print("Enrollment token not found. Run scripts/bootstrap_local.py or set QWR_ENROLLMENT_TOKEN.")
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
