#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from response_agent import AgentConfig


class HandoffError(RuntimeError):
    pass


_SUBJECT_TOKEN = re.compile(r"^[0-9a-f]{32}$")


def _derive_hmac_key(secret: str) -> bytes:
    return hashlib.sha256(("quietward-response-v1:" + secret).encode("utf-8")).digest()


def _headers(config: AgentConfig, target: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(["POST", target, timestamp, nonce, body_hash]).encode("utf-8")
    signature = hmac.new(_derive_hmac_key(config.secret), canonical, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-QWR-Agent-ID": config.agent_id,
        "X-QWR-Key-ID": config.key_id,
        "X-QWR-Timestamp": timestamp,
        "X-QWR-Nonce": nonce,
        "X-QWR-Signature": signature,
    }


def _load_handoff(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HandoffError(f"handoff file is unreadable or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise HandoffError("handoff root must be an object")
    if value.get("format") != "quietward-response-handoff-v1":
        raise HandoffError("handoff format is not supported")
    safety = value.get("safety")
    if not isinstance(safety, dict):
        raise HandoffError("handoff safety declaration is missing")
    required_safety = {
        "observation_only_source": True,
        "actions_executed": 0,
        "executable_authority": False,
        "raw_finding_subjects_included": False,
        "network_request_performed": False,
    }
    if any(safety.get(key) != expected for key, expected in required_safety.items()):
        raise HandoffError("handoff does not satisfy the observation-only safety contract")
    events = value.get("events")
    if not isinstance(events, list) or len(events) > 1000:
        raise HandoffError("handoff events must be a list with at most 1000 items")
    return value


def _validate_event(event: Any, config: AgentConfig) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise HandoffError("handoff event must be an object")
    if event.get("schema_version") != "1.0" or event.get("source") != "quietward":
        raise HandoffError("handoff event source/schema is invalid")
    if event.get("host_id") != config.host_id:
        raise HandoffError("handoff event host does not match the enrolled Response agent")
    metadata = event.get("metadata")
    evidence = event.get("evidence")
    if not isinstance(metadata, dict) or not isinstance(evidence, dict):
        raise HandoffError("handoff event metadata/evidence is invalid")
    if metadata.get("observation_only_source") is not True:
        raise HandoffError("handoff event is not marked observation-only")
    if metadata.get("executable_authority") is not False:
        raise HandoffError("handoff event claims executable authority")
    if metadata.get("quietward_response_context_version") != "1.0":
        raise HandoffError("handoff event context version is invalid")
    subject_token = evidence.get("subject_hmac_sha256")
    if not isinstance(subject_token, str) or not _SUBJECT_TOKEN.fullmatch(subject_token):
        raise HandoffError("handoff event subject identity is not privacy-keyed")
    for sensitive_surface in ("process", "file", "network", "persistence"):
        if event.get(sensitive_surface) is not None:
            raise HandoffError(f"handoff event unexpectedly includes raw {sensitive_surface} context")
    summary = str(event.get("summary") or "")
    if not summary or len(summary) > 2048:
        raise HandoffError("handoff event summary is invalid")
    return event


def _post_event(config: AgentConfig, event: dict[str, Any]) -> str:
    target = "/api/v1/events"
    body = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = Request(
        config.base_url + target,
        data=body,
        method="POST",
        headers=_headers(config, target, body),
    )
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:
            result = json.loads(response.read())
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        try:
            parsed = json.loads(detail)
        except json.JSONDecodeError:
            parsed = None
        code = (
            parsed.get("detail", {}).get("code")
            if isinstance(parsed, dict) and isinstance(parsed.get("detail"), dict)
            else None
        )
        if exc.code == 409 and code == "duplicate_event_id":
            return "duplicate"
        raise HandoffError(f"Response rejected handoff event with HTTP {exc.code}: {detail}") from exc
    except (URLError, OSError) as exc:
        raise HandoffError(f"Response API unavailable: {exc}") from exc
    if not isinstance(result, dict) or result.get("accepted") is not True:
        raise HandoffError("Response returned an invalid ingestion result")
    return "sent"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest a sanitized local QuietWard handoff using a Response-owned agent credential"
    )
    parser.add_argument("handoff", type=Path)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()

    config = AgentConfig.from_file(args.config)
    handoff = _load_handoff(args.handoff)
    events = [_validate_event(event, config) for event in handoff["events"]]
    sent = 0
    duplicates = 0
    for event in events:
        outcome = _post_event(config, event)
        sent += int(outcome == "sent")
        duplicates += int(outcome == "duplicate")
    print(
        json.dumps(
            {
                "accepted": sent,
                "duplicates": duplicates,
                "total": len(events),
                "host_id": config.host_id,
                "source": "quietward",
                "observation_only_handoff": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HandoffError as exc:
        print(f"QuietWard handoff ingestion failed: {exc}")
        raise SystemExit(1)
