#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_RESPONSE_BRANCH = "feature/phase2-secure-integration"
EXPECTED_QUIETWARD_BRANCH = "feature/response-platform-integration"
SUPPORTED_RESPONSE_VERSIONS = {"1.0.0rc1", "1.0.0"}


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


def _fetch_release_refs(repo: Path) -> None:
    subprocess.run(
        ["git", "fetch", "origin", "--prune", "--tags"],
        cwd=repo,
        check=True,
    )


def _remote_repo_name(remote: str) -> str:
    return remote.rstrip("/").removesuffix(".git").rsplit("/", 1)[-1]


def _response_version() -> str:
    text = (ROOT / "backend" / "app" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None or match.group(1) not in SUPPORTED_RESPONSE_VERSIONS:
        raise RuntimeError("Response version is missing or is not an expected v1 version")
    return match.group(1)


def _verify_checkout(repo: Path, *, expected_branch: str, expected_repo_name: str) -> str:
    if not (repo / ".git").exists():
        raise RuntimeError(f"not a git checkout: {repo}")
    branch = _git(repo, "branch", "--show-current")
    if branch != expected_branch:
        raise RuntimeError(f"{repo.name}: expected branch {expected_branch!r}, found {branch!r}")
    remote = _git(repo, "remote", "get-url", "origin")
    if _remote_repo_name(remote) != expected_repo_name:
        raise RuntimeError(f"{repo.name}: origin is not the expected {expected_repo_name} repository: {remote}")
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError(f"{repo.name}: tracked working tree changes must be committed before release verification:\n{dirty}")
    tracked_env = _git(repo, "ls-files", ".env")
    if tracked_env:
        raise RuntimeError(f"{repo.name}: .env must not be tracked")

    # Qualification must apply to the exact code currently pushed to GitHub, not a
    # stale or unpushed local branch. Fetching also gives the publication audit all
    # currently reachable remote branch/tag history to inspect.
    _fetch_release_refs(repo)
    local_head = _git(repo, "rev-parse", "HEAD")
    remote_head = _git(repo, "rev-parse", f"origin/{expected_branch}")
    if local_head != remote_head:
        raise RuntimeError(
            f"{repo.name}: local HEAD {local_head} does not match origin/{expected_branch} {remote_head}"
        )

    # The release branch must contain the current default main branch; otherwise a
    # merge could accidentally omit a newer fix already present on main.
    contains_main = subprocess.run(
        ["git", "merge-base", "--is-ancestor", "origin/main", "HEAD"],
        cwd=repo,
    ).returncode
    if contains_main != 0:
        raise RuntimeError(
            f"{repo.name}: {expected_branch} does not contain current origin/main"
        )
    return local_head


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete QuietWard Response v1 automated release gates."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward = args.quietward_repo.resolve()
    version = _response_version()
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
    print(f"response_version={version}")
    print(f"response_head={response_head}")
    print(f"quietward_head={quietward_head}")
    print("npm audit was required and was not skipped.")
    print("Both local release branches matched their current GitHub refs and contained origin/main.")
    if version == "1.0.0rc1":
        print("Next: perform the UI smoke check, then run scripts/promote_v1.py, commit/push those version-only changes, and rerun this complete gate.")
    else:
        print("Version is final 1.0.0. Remaining release step: documented UI smoke check, then merge/tag/publication if clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
