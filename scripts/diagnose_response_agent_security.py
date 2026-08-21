#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import stat
from dataclasses import dataclass
from pathlib import Path

try:
    from response_agent import AgentConfig, ResponseAgentError
except ImportError:  # package-style test import
    from scripts.response_agent import AgentConfig, ResponseAgentError


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str


def _posix_private_mode(path: Path, *, directory: bool) -> Check:
    if os.name == "nt":
        return Check(
            "permissions",
            "WARN",
            "POSIX mode checks do not validate Windows ACLs; use OS-backed ACL/secret-store qualification",
        )
    mode = stat.S_IMODE(path.stat().st_mode)
    writable_by_others = bool(mode & 0o022)
    readable_by_others = bool(mode & 0o044)
    if writable_by_others:
        return Check(
            "permissions",
            "FAIL",
            f"{path} is group/world writable (mode {mode:o})",
        )
    if not directory and readable_by_others:
        return Check(
            "permissions",
            "FAIL",
            f"credential config is group/world readable (mode {mode:o})",
        )
    return Check("permissions", "PASS", f"private enough mode {mode:o}: {path}")


def diagnose(config_path: Path) -> list[Check]:
    path = config_path.expanduser()
    if not path.is_absolute():
        raise ResponseAgentError("Response agent config path must be absolute")
    if path.is_symlink():
        raise ResponseAgentError("Response agent config must not be a symbolic link")
    config = AgentConfig.from_file(path)
    checks: list[Check] = []

    checks.append(_posix_private_mode(path, directory=False))

    if not config.state_dir.exists():
        checks.append(Check("state_directory", "WARN", "state directory does not exist yet"))
    elif not config.state_dir.is_dir() or config.state_dir.is_symlink():
        checks.append(Check("state_directory", "FAIL", "state directory is not a normal directory"))
    else:
        state_mode = _posix_private_mode(config.state_dir, directory=True)
        checks.append(Check("state_directory", state_mode.status, state_mode.detail))

    checks.append(
        Check(
            "transport",
            "PASS",
            "agent URL passed loopback-HTTP/remote-HTTPS validation",
        )
    )

    if len(config.secret) < 32:
        checks.append(Check("credential", "FAIL", "agent secret is unexpectedly short"))
    else:
        checks.append(Check("credential", "PASS", "agent credential has expected entropy length"))

    if config.enable_process_termination:
        checks.append(
            Check(
                "process_termination",
                "WARN",
                "high-impact process termination is locally enabled",
            )
        )
    else:
        checks.append(Check("process_termination", "PASS", "process termination is locally disabled"))

    if config.enable_file_quarantine:
        if not config.managed_roots:
            checks.append(Check("file_quarantine", "FAIL", "quarantine enabled with no managed roots"))
        else:
            checks.append(
                Check(
                    "file_quarantine",
                    "WARN",
                    f"managed-file quarantine is locally enabled for {len(config.managed_roots)} root(s)",
                )
            )
    else:
        checks.append(Check("file_quarantine", "PASS", "file quarantine is locally disabled"))

    existing_roots: list[Path] = []
    for root in config.managed_roots:
        if root.is_symlink():
            checks.append(Check("managed_root", "FAIL", f"managed root is a symlink: {root}"))
        elif not root.exists() or not root.is_dir():
            checks.append(Check("managed_root", "FAIL", f"managed root is unavailable: {root}"))
        else:
            existing_roots.append(root.resolve())
            checks.append(Check("managed_root", "PASS", f"managed root available: {root}"))

    quarantine = Path(config.quarantine_dir)
    if quarantine.exists():
        if quarantine.is_symlink() or not quarantine.is_dir():
            checks.append(Check("quarantine_directory", "FAIL", "quarantine path is not a normal directory"))
        else:
            mode_check = _posix_private_mode(quarantine, directory=True)
            checks.append(Check("quarantine_directory", mode_check.status, mode_check.detail))
            try:
                quarantine_device = quarantine.stat().st_dev
            except OSError:
                quarantine_device = None
            for root in existing_roots:
                try:
                    root_device = root.stat().st_dev
                except OSError:
                    continue
                if quarantine_device is not None and root_device != quarantine_device:
                    checks.append(
                        Check(
                            "quarantine_filesystem",
                            "WARN",
                            f"managed root {root} and quarantine directory are on different filesystems; move may require copy/delete semantics",
                        )
                    )
    elif config.enable_file_quarantine:
        checks.append(
            Check(
                "quarantine_directory",
                "WARN",
                "quarantine directory does not exist yet; agent will create it privately on first use",
            )
        )

    return checks


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run read-only local security checks for a QuietWard Response agent configuration."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat WARN results, including enabled high-impact capabilities, as failure.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    checks = diagnose(args.config)
    print("QUIETWARD RESPONSE AGENT SECURITY DIAGNOSTIC")
    for item in checks:
        print(f"{item.status:4} {item.name}: {item.detail}")
    print("The agent secret was inspected only for length and was not printed.")
    if any(item.status == "FAIL" for item in checks):
        return 1
    if args.strict and any(item.status == "WARN" for item in checks):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
