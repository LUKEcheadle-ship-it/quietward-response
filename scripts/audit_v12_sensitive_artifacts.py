#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

_EXACT_BLOCKED_NAMES = {
    "agent.json",
    "response-agent.json",
    "response_agent.json",
    "quietward-response-agent.json",
    "quietward_response_agent.json",
    "agent-config.json",
    "agent_config.json",
}
_SECRET_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
)


def _tracked_paths() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return [
        Path(raw.decode("utf-8"))
        for raw in completed.stdout.split(b"\0")
        if raw
    ]


def _reason(path: Path) -> str | None:
    name = path.name.casefold()
    full = path.as_posix().casefold()

    if name in _EXACT_BLOCKED_NAMES:
        return "agent credential/config filename"

    # rotate_response_agent_key.py stages the new secret as `<config>.next`.
    # Any such tracked sidecar is credential material, regardless of its JSON name.
    if name.endswith(".next") and (
        "agent" in name
        or "response" in name
        or "quietward" in name
        or "/agent" in full
    ):
        return "staged agent rotation credential (.next)"

    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment secret file"

    if name.endswith(_SECRET_SUFFIXES):
        return "private key/certificate container"

    return None


def main() -> int:
    findings: list[tuple[Path, str]] = []
    for path in _tracked_paths():
        reason = _reason(path)
        if reason:
            findings.append((path, reason))

    if findings:
        print("V1.2 SENSITIVE ARTIFACT AUDIT: FAIL")
        for path, reason in findings:
            print(f"{path.as_posix()}: {reason}")
        return 1

    print("V1.2 SENSITIVE ARTIFACT AUDIT: PASS")
    print("tracked_agent_credentials=0")
    print("tracked_staged_rotation_credentials=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
