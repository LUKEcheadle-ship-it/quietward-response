#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_TEXT_BYTES = 2_000_000

BLOCKED_EXACT_PATHS = {
    ".env",
    "backend/quietward-response.db",
    "quietward-response.db",
}
BLOCKED_SECRET_FILENAMES = {
    "agent.json",
    "response-agent.json",
    "response-agent-config.json",
}
BLOCKED_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".p12",
    ".pfx",
    ".key",
}
SAFE_ENV_FILES = {".env.example"}

HIGH_CONFIDENCE_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("OpenAI-style secret", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
)

PRIVATE_MACHINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private homelab path", re.compile(r"/home/homelab/", re.IGNORECASE)),
    (
        "private Windows profile path",
        re.compile(
            r"[A-Za-z]:\\Users\\(?!Public(?:\\|$)|Default(?:\\|$)|USERNAME(?:\\|$)|USER(?:\\|$))[^\\\r\n]+\\",
            re.IGNORECASE,
        ),
    ),
)


def _git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )
    return completed.stdout


def _tracked_files() -> list[Path]:
    raw = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return [ROOT / item.decode("utf-8") for item in raw.split(b"\0") if item]


def _is_blocked_path(relative: str) -> str | None:
    normalized = relative.replace("\\", "/")
    name = Path(normalized).name
    lower_name = name.lower()
    if normalized.startswith(".github/workflows/"):
        return "GitHub Actions workflows are not permitted in the Response release tree"
    if normalized in BLOCKED_EXACT_PATHS:
        return "local runtime/secret file must not be tracked"
    if lower_name in BLOCKED_SECRET_FILENAMES:
        return "Response agent credential/config file must not be tracked"
    if lower_name.endswith(".next") and lower_name[:-5] in BLOCKED_SECRET_FILENAMES:
        return "staged Response agent credential sidecar must not be tracked"
    if name.startswith(".env") and normalized not in SAFE_ENV_FILES:
        return "environment file must not be tracked"
    suffix = Path(normalized).suffix.lower()
    if suffix in BLOCKED_SUFFIXES:
        return f"sensitive/runtime file type is not public-release safe: {suffix}"
    return None


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read tracked file {path}: {exc}") from exc
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scan_text(label: str, text: str, *, include_machine_paths: bool) -> list[str]:
    findings: list[str] = []
    for kind, pattern in HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"{label}: possible {kind}")
    if include_machine_paths:
        for kind, pattern in PRIVATE_MACHINE_PATTERNS:
            if pattern.search(text):
                findings.append(f"{label}: {kind}")
    return findings


def main() -> int:
    findings: list[str] = []
    tracked = _tracked_files()

    for path in tracked:
        relative = path.relative_to(ROOT).as_posix()
        blocked = _is_blocked_path(relative)
        if blocked:
            findings.append(f"{relative}: {blocked}")
            continue
        text = _read_text(path)
        if text is not None:
            findings.extend(_scan_text(relative, text, include_machine_paths=True))

    history_names = _git("log", "--all", "--name-only", "--pretty=format:")
    for raw_name in history_names.splitlines():
        name = raw_name.strip().replace("\\", "/")
        if not name:
            continue
        blocked = _is_blocked_path(name)
        if blocked:
            findings.append(f"history:{name}: {blocked}")

    history_patch = _git(
        "log",
        "--all",
        "-p",
        "--no-color",
        "--no-ext-diff",
        "--format=commit %H",
    )
    findings.extend(_scan_text("git history", history_patch, include_machine_paths=False))

    unique = sorted(set(findings))
    if unique:
        print("PUBLIC RELEASE AUDIT: FAIL")
        for finding in unique:
            print(f"- {finding}")
        return 1

    print(f"PUBLIC RELEASE AUDIT: PASS ({len(tracked)} tracked files checked)")
    print("High-confidence secret patterns and sensitive tracked/history paths: clear")
    print("Private machine path checks on current tracked text: clear")
    print("GitHub Actions workflows: absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
