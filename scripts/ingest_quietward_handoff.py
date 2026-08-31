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
_SAFE_CODE = re.compile(r"^[a-z0-9_.:+-]{1,64}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
_ALLOWED_CATEGORIES = {
    "malware",
    "integrity",
    "privilege",
    "persistence",
    "identity",
    "network",
    "container",
    "vulnerability",
    "execution",
    "file_integrity",
    "operational",
    "security",
}
_ALLOWED_SUBJECT_TYPES = {
    "file",
    "process",
    "network",
    "persistence",
    "identity",
    "container",
    "host_or_other",
}
_ALLOWED_HINTS = {
    "host_health",
    "process_inventory",
    "network_snapshot",
    "artifact_metadata_review",
}
_ALLOWED_OS = {None, "Windows", "Linux", "Darwin", "Unknown"}
_ALLOWED_EVENT_KEYS = {
    "schema_version",
    "event_id",
    "source",
    "source_version",
    "host_id",
    "host_name",
    "timestamp",
    "event_type",
    "category",
    "severity",
    "confidence",
    "summary",
    "evidence",
    "process",
    "file",
    "network",
    "persistence",
    "metadata",
}
_ALLOWED_EVIDENCE_KEYS = {
    "event_count",
    "event_kinds",
    "correlation_signal_codes",
    "subject_hmac_sha256",
    "subject_type",
}
_ALLOWED_METADATA_KEYS = {
    "quietward_response_context_version",
    "quietward_finding_id",
    "quietward_score",
    "quietward_mode",
    "requires_human_approval",
    "observation_only_source",
    "executable_authority",
    "investigation_hints",
    "operating_system",
}


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
    if set(safety) != set(required_safety):
        raise HandoffError("handoff safety declaration contains unexpected fields")
    if any(safety.get(key) != expected for key, expected in required_safety.items()):
        raise HandoffError("handoff does not satisfy the observation-only safety contract")
    events = value.get("events")
    if not isinstance(events, list) or len(events) > 1000:
        raise HandoffError("handoff events must be a list with at most 1000 items")
    return value


def _safe_string_list(value: Any, *, label: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise HandoffError(f"handoff {label} is invalid")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _SAFE_CODE.fullmatch(item):
            raise HandoffError(f"handoff {label} contains an invalid code")
        result.append(item)
    if len(result) != len(set(result)):
        raise HandoffError(f"handoff {label} contains duplicate codes")
    return result


def _validate_event(event: Any, config: AgentConfig) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise HandoffError("handoff event must be an object")
    if set(event) != _ALLOWED_EVENT_KEYS:
        raise HandoffError("handoff event contains unexpected top-level fields")
    if event.get("schema_version") != "1.0" or event.get("source") != "quietward":
        raise HandoffError("handoff event source/schema is invalid")
    if event.get("host_id") != config.host_id:
        raise HandoffError("handoff event host does not match the enrolled Response agent")
    if event.get("host_name") is not None:
        raise HandoffError("handoff event must not include a host name")
    source_version = event.get("source_version")
    if source_version is not None and (
        not isinstance(source_version, str) or not _SAFE_VERSION.fullmatch(source_version)
    ):
        raise HandoffError("handoff source version is invalid")

    category = event.get("category")
    severity = event.get("severity")
    if category not in _ALLOWED_CATEGORIES:
        raise HandoffError("handoff event category is invalid")
    if severity not in {"info", "informational", "low", "medium", "high", "critical"}:
        raise HandoffError("handoff event severity is invalid")
    if event.get("event_type") != f"quietward_{category}_finding":
        raise HandoffError("handoff event type does not match its category")

    metadata = event.get("metadata")
    evidence = event.get("evidence")
    if not isinstance(metadata, dict) or not isinstance(evidence, dict):
        raise HandoffError("handoff event metadata/evidence is invalid")
    if set(metadata) != _ALLOWED_METADATA_KEYS:
        raise HandoffError("handoff metadata contains unexpected fields")
    if set(evidence) != _ALLOWED_EVIDENCE_KEYS:
        raise HandoffError("handoff evidence contains unexpected fields")
    if metadata.get("observation_only_source") is not True:
        raise HandoffError("handoff event is not marked observation-only")
    if metadata.get("executable_authority") is not False:
        raise HandoffError("handoff event claims executable authority")
    if metadata.get("quietward_response_context_version") != "1.0":
        raise HandoffError("handoff event context version is invalid")
    if metadata.get("operating_system") not in _ALLOWED_OS:
        raise HandoffError("handoff event operating-system family is invalid")
    if not isinstance(metadata.get("requires_human_approval"), bool):
        raise HandoffError("handoff human-approval marker is invalid")
    hints = _safe_string_list(
        metadata.get("investigation_hints"),
        label="investigation hints",
        maximum=8,
    )
    if not set(hints).issubset(_ALLOWED_HINTS):
        raise HandoffError("handoff contains an unknown investigation hint")

    subject_token = evidence.get("subject_hmac_sha256")
    if not isinstance(subject_token, str) or not _SUBJECT_TOKEN.fullmatch(subject_token):
        raise HandoffError("handoff event subject identity is not privacy-keyed")
    if evidence.get("subject_type") not in _ALLOWED_SUBJECT_TYPES:
        raise HandoffError("handoff event subject type is invalid")
    event_count = evidence.get("event_count")
    if not isinstance(event_count, int) or isinstance(event_count, bool) or not 1 <= event_count <= 10000:
        raise HandoffError("handoff event count is invalid")
    _safe_string_list(evidence.get("event_kinds"), label="event kinds", maximum=24)
    _safe_string_list(
        evidence.get("correlation_signal_codes"),
        label="correlation signal codes",
        maximum=24,
    )

    for sensitive_surface in ("process", "file", "network", "persistence"):
        if event.get(sensitive_surface) is not None:
            raise HandoffError(f"handoff event unexpectedly includes raw {sensitive_surface} context")
    expected_summary = (
        f"QuietWard correlated {event_count} evidence item(s) into a {severity} {category} finding."
    )
    if event.get("summary") != expected_summary:
        raise HandoffError("handoff event summary is not the sanitized canonical form")
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
