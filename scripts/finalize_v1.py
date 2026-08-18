#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run both QuietWard Response v1 automated release gates in order."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    parser.add_argument("--skip-npm-audit", action="store_true")
    args = parser.parse_args()

    quietward = args.quietward_repo.resolve()
    static_command = [
        sys.executable,
        str(ROOT / "scripts" / "verify_v1.py"),
        "--quietward-repo",
        str(quietward),
    ]
    if args.skip_npm_audit:
        static_command.append("--skip-npm-audit")

    subprocess.run(static_command, cwd=ROOT, check=True)
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
    print("Remaining release step: perform the documented UI smoke check, then promote rc1 to 1.0.0 and merge the staged PRs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
