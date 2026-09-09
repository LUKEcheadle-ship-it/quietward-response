#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str]) -> None:
    print("\n>>> " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


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
