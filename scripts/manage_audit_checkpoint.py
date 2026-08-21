#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class CheckpointToolError(RuntimeError):
    pass


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_MAX_RESPONSE_BYTES = 64 * 1024


def _base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CheckpointToolError("API URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise CheckpointToolError("API URL must not contain embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise CheckpointToolError("API URL must not contain a path, query, or fragment")
    hostname = parsed.hostname.lower()
    loopback = hostname in _LOOPBACK_HOSTS or hostname.endswith(".localhost")
    if parsed.scheme == "http" and not loopback:
        raise CheckpointToolError("plain HTTP is allowed only for loopback Response; use HTTPS otherwise")
    return normalized


def _analyst_token(explicit: str | None) -> str:
    token = str(explicit or os.environ.get("QWR_ANALYST_TOKEN") or "").strip()
    if not token:
        token = getpass.getpass("Response analyst bearer token: ").strip()
    if not token:
        raise CheckpointToolError("analyst bearer token is required")
    if len(token) > 512:
        raise CheckpointToolError("analyst bearer token is unexpectedly long")
    return token


def _request_json(
    base_url: str,
    token: str,
    target: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = None
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    if payload is not None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(base_url + target, data=body, method=method, headers=headers)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise CheckpointToolError(f"Response API HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise CheckpointToolError(f"Response API unavailable: {exc}") from exc
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise CheckpointToolError("Response API returned an unexpectedly large checkpoint response")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckpointToolError("Response API returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise CheckpointToolError("Response API returned a non-object checkpoint response")
    return value


def _validate_checkpoint(value: dict[str, Any]) -> None:
    expected = {"schema_version", "generated_at", "entries_checked", "head_hash", "signature"}
    if set(value) != expected:
        raise CheckpointToolError("checkpoint response has an unexpected field set")
    if value.get("schema_version") != "1.0":
        raise CheckpointToolError("checkpoint schema version is not supported")
    if not isinstance(value.get("generated_at"), str) or not value["generated_at"]:
        raise CheckpointToolError("checkpoint generated_at is invalid")
    entries = value.get("entries_checked")
    if not isinstance(entries, int) or entries < 0:
        raise CheckpointToolError("checkpoint entries_checked is invalid")
    for field in ("head_hash", "signature"):
        item = value.get(field)
        if not isinstance(item, str) or len(item) != 64:
            raise CheckpointToolError(f"checkpoint {field} must be a 64-character digest")
        if any(char not in "0123456789abcdefABCDEF" for char in item):
            raise CheckpointToolError(f"checkpoint {field} must be hexadecimal")


def _atomic_private_json(path: Path, value: dict[str, Any], *, force: bool) -> Path:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise CheckpointToolError("checkpoint output path must be absolute")
    if resolved.exists() and not force:
        raise CheckpointToolError(f"checkpoint output already exists: {resolved}")
    resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = resolved.with_name(resolved.name + ".tmp")
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short checkpoint write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, resolved)
    try:
        resolved.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return resolved


def _load_checkpoint(path: Path) -> dict[str, Any]:
    resolved = path.expanduser()
    if not resolved.is_absolute():
        raise CheckpointToolError("checkpoint path must be absolute")
    if resolved.is_symlink():
        raise CheckpointToolError("checkpoint path must not be a symbolic link")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise CheckpointToolError(f"unable to read checkpoint: {resolved}") from exc
    if len(raw) > 16_384:
        raise CheckpointToolError("checkpoint file is unexpectedly large")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CheckpointToolError("checkpoint file contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise CheckpointToolError("checkpoint file must contain a JSON object")
    _validate_checkpoint(value)
    return value


def export_checkpoint(base_url: str, token: str, path: Path, *, force: bool = False) -> dict[str, Any]:
    checkpoint = _request_json(base_url, token, "/api/v1/audit/checkpoint")
    _validate_checkpoint(checkpoint)
    _atomic_private_json(path, checkpoint, force=force)
    return checkpoint


def verify_checkpoint(base_url: str, token: str, path: Path) -> dict[str, Any]:
    checkpoint = _load_checkpoint(path)
    result = _request_json(
        base_url,
        token,
        "/api/v1/audit/checkpoint/verify",
        method="POST",
        payload=checkpoint,
    )
    if result.get("valid") is not True:
        raise CheckpointToolError(
            "retained checkpoint verification failed: " + str(result.get("error") or "unknown")
        )
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export or verify a retained QuietWard Response signed audit checkpoint."
    )
    parser.add_argument("command", choices=("export", "verify"))
    parser.add_argument("--api-url", default="http://127.0.0.1:8002")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument(
        "--token",
        help="Analyst bearer token. Prefer QWR_ANALYST_TOKEN or interactive prompt to avoid process-list exposure.",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing export file.")
    return parser


def main() -> int:
    args = _parser().parse_args()
    base_url = _base_url(args.api_url)
    token = _analyst_token(args.token)
    path = args.file.expanduser()

    if args.command == "export":
        checkpoint = export_checkpoint(base_url, token, path, force=args.force)
        print(f"Signed audit checkpoint exported: {path.resolve()}")
        print(f"Entries anchored: {checkpoint['entries_checked']}")
        print(f"Audit head: {checkpoint['head_hash']}")
        print("The analyst bearer token was not printed or written to the checkpoint file.")
        return 0

    result = verify_checkpoint(base_url, token, path)
    print(f"Signed audit checkpoint verified: {path.resolve()}")
    print(f"Anchored entries: {result.get('entries_checked')}")
    print(f"Current entries: {result.get('current_entries_checked')}")
    print("The analyst bearer token was not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
