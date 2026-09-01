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
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
AGENT_VERSION = "1.1.0a1"
AGENT_ACTIONS = [
    "collect_host_diagnostic",
    "collect_network_diagnostic",
    "collect_process_diagnostic",
    "restart_quietward_demo_service",
]


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
            value = stripped[len(prefix) :].strip()
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
    loopback = parsed.hostname.lower() in {"127.0.0.1", "::1", "localhost"} or parsed.hostname.lower().endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise ValueError("plain HTTP enrollment is allowed only on loopback; use HTTPS otherwise")
    return resolved


def _resolve_api_url(explicit: str | None) -> str:
    if explicit:
        return _validated_api_url(explicit)
    port = os.environ.get("QWR_API_PORT") or _env_file_value("QWR_API_PORT") or "8002"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("QWR_API_PORT must be a valid TCP port")
    return f"http://127.0.0.1:{int(port)}"


def _default_state_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return (base / "QuietWardResponse" / "agent").resolve()
    return (Path.home() / ".local" / "state" / "quietward-response" / "agent").resolve()


def _private_json(path: Path, value: dict[str, object], *, force: bool) -> None:
    if not path.is_absolute():
        raise ValueError("agent config path must be absolute")
    if path.exists() and not force:
        raise ValueError(f"agent config already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("short agent-config write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _signed_headers(
    *,
    agent_id: str,
    key_id: str,
    secret: str,
    method: str,
    target: str,
    body: bytes,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join([method.upper(), target, timestamp, nonce, body_hash]).encode("utf-8")
    signature = hmac.new(_derive_hmac_key(secret), canonical, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": agent_id,
        "X-QWR-Key-ID": key_id,
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": signature,
    }


def _report_capabilities(api_url: str, enrolled: dict[str, object]) -> None:
    agent_id = str(enrolled["agent_id"])
    key_id = str(enrolled["key_id"])
    secret = str(enrolled["secret"])
    target = f"/api/v1/agents/{agent_id}/capabilities"
    body = json.dumps(
        {
            "schema_version": "1.0",
            "agent_version": AGENT_VERSION,
            "supported_actions": AGENT_ACTIONS,
            "enabled_actions": AGENT_ACTIONS,
            "arbitrary_command_execution": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        api_url + target,
        data=body,
        method="POST",
        headers=_signed_headers(
            agent_id=agent_id,
            key_id=key_id,
            secret=secret,
            method="POST",
            target=target,
            body=body,
        ),
    )
    try:
        with urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"capability registration failed with HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise RuntimeError(f"capability registration failed: {exc}") from exc
    if not isinstance(result, dict) or result.get("agent_id") != agent_id:
        raise RuntimeError("capability registration returned an invalid response")


def main() -> int:
    parser = argparse.ArgumentParser(description="Enroll the separate QuietWard Response diagnostic agent")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--api-url")
    parser.add_argument("--display-name")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    token = os.environ.get("QWR_ENROLLMENT_TOKEN") or _env_file_value("QWR_ENROLLMENT_TOKEN")
    if not token:
        print("Enrollment token not found in QWR_ENROLLMENT_TOKEN or repository .env")
        return 2
    try:
        api_url = _resolve_api_url(args.api_url)
    except ValueError as exc:
        print(str(exc))
        return 2

    state_dir = (args.state_dir or _default_state_dir()).expanduser().resolve()
    config_path = (args.config or state_dir / "agent-config.json").expanduser().resolve()
    payload = json.dumps(
        {
            "host_id": args.host_id,
            "display_name": args.display_name or f"Response diagnostic agent on {args.host_id}",
            "agent_version": AGENT_VERSION,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        api_url + "/api/v1/agents/enroll",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "X-QWR-Enrollment-Token": token},
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

    try:
        _private_json(
            config_path,
            {
                "base_url": api_url,
                "agent_id": enrolled["agent_id"],
                "key_id": enrolled["key_id"],
                "secret": enrolled["secret"],
                "host_id": enrolled["host_id"],
                "state_dir": str(state_dir),
                "timeout_seconds": 5.0,
            },
            force=args.force,
        )
    except (KeyError, OSError, ValueError) as exc:
        print(f"Enrollment succeeded but private config creation failed: {exc}")
        return 1

    try:
        _report_capabilities(api_url, enrolled)
    except (KeyError, RuntimeError) as exc:
        print(f"Agent config was stored privately, but signed capability registration failed: {exc}")
        return 1

    print(f"Response diagnostic agent enrolled. Private config: {config_path}")
    print("Signed diagnostic capabilities registered. The one-time enrollment secret was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
