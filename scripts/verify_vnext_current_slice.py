#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_BRANCH = "feature/guided-incident-response-vnext"


def _run(command: list[str]) -> None:
    print("\n>>> " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _require_feature_checkout(repo: Path, label: str) -> str:
    if not (repo / ".git").exists():
        raise RuntimeError(f"{label} is not a git checkout: {repo}")
    branch = _git(repo, "branch", "--show-current")
    if branch != EXPECTED_BRANCH:
        raise RuntimeError(
            f"{label} must be on {EXPECTED_BRANCH!r} for paired vNext testing; found {branch!r}"
        )
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError(
            f"{label} has tracked working-tree changes; commit/stash them before qualification:\n{dirty}"
        )
    return _git(repo, "rev-parse", "HEAD")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify the currently implemented QuietWard + Response vNext slice. "
            "This is intentionally separate from the final resolution-coverage release gate."
        )
    )
    parser.add_argument(
        "--quietward-repo",
        type=Path,
        required=True,
        help="Path to the companion QuietWard feature-branch checkout.",
    )
    parser.add_argument(
        "--skip-npm-audit",
        action="store_true",
        help="Development/offline only. A run using this flag is not release qualification.",
    )
    args = parser.parse_args()

    quietward_repo = args.quietward_repo.expanduser().resolve()
    if not (quietward_repo / "src" / "quietward").is_dir():
        raise RuntimeError(f"not a QuietWard checkout: {quietward_repo}")

    response_head = _require_feature_checkout(ROOT, "QuietWard Response")
    quietward_head = _require_feature_checkout(quietward_repo, "QuietWard")
    print(f"Response feature HEAD: {response_head}")
    print(f"QuietWard feature HEAD: {quietward_head}")

    development_gate = [
        sys.executable,
        str(ROOT / "scripts" / "verify_v11_diagnostics.py"),
        "--quietward-repo",
        str(quietward_repo),
    ]
    if args.skip_npm_audit:
        development_gate.append("--skip-npm-audit")

    _run(development_gate)
    _run([sys.executable, str(ROOT / "scripts" / "verify_vnext_process_containment.py")])

    coverage = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_vnext_resolution_coverage.py")],
        cwd=ROOT,
        check=False,
    )
    if coverage.returncode not in {0, 1}:
        raise RuntimeError(
            f"resolution coverage gate exited unexpectedly with {coverage.returncode}"
        )

    print("\nVNEXT CURRENT IMPLEMENTED SLICE: PASS")
    print(f"- response_head={response_head}")
    print(f"- quietward_head={quietward_head}")
    print("- Response backend/frontend/migration/public-release development gates passed")
    print("- companion QuietWard suite and live joint acceptance passed")
    print("- disposable evidence-bound process containment passed")
    if coverage.returncode == 0:
        print("- final resolution coverage gate also passed")
    else:
        print("- final combined release remains BLOCKED by unfinished resolution families (expected)")
    if args.skip_npm_audit:
        print("- npm audit was skipped, so this run is development-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
