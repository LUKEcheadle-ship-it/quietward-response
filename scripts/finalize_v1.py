#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RESPONSE_BRANCH = "feature/phase2-secure-integration"
EXPECTED_QUIETWARD_BRANCH = "feature/response-platform-integration"


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout.strip()


def _verify_checkout(repo: Path, *, expected_branch: str, expected_repo_name: str) -> str:
    if not (repo / ".git").exists():
        raise RuntimeError(f"not a git checkout: {repo}")
    branch = _git(repo, "branch", "--show-current")
    if branch != expected_branch:
        raise RuntimeError(f"{repo.name}: expected branch {expected_branch!r}, found {branch!r}")
    remote = _git(repo, "remote", "get-url", "origin")
    if expected_repo_name not in remote:
        raise RuntimeError(f"{repo.name}: origin does not look like {expected_repo_name}: {remote}")
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError(f"{repo.name}: tracked working tree changes must be committed before release verification:\n{dirty}")
    tracked_env = _git(repo, "ls-files", ".env")
    if tracked_env:
        raise RuntimeError(f"{repo.name}: .env must not be tracked")
    return _git(repo, "rev-parse", "HEAD")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete QuietWard Response v1 automated release gates."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward = args.quietward_repo.resolve()
    response_head = _verify_checkout(
        ROOT,
        expected_branch=EXPECTED_RESPONSE_BRANCH,
        expected_repo_name="quietward-response",
    )
    quietward_head = _verify_checkout(
        quietward,
        expected_branch=EXPECTED_QUIETWARD_BRANCH,
        expected_repo_name="quietward",
    )

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_v1.py"),
            "--quietward-repo",
            str(quietward),
        ],
        cwd=ROOT,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_v1_live.py"),
            "--quietward-repo",
            str(quietward),
        ],
        cwd=ROOT,
        check=True,
    )

    print("\nQUIETWARD RESPONSE V1 AUTOMATED GATES: PASS")
    print(f"response_head={response_head}")
    print(f"quietward_head={quietward_head}")
    print("npm audit was required and was not skipped.")
    print("Remaining release step: perform the documented UI smoke check, then promote rc1 to 1.0.0 and merge the staged PRs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
