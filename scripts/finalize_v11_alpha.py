#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

from finalize_v1 import (
    EXPECTED_QUIETWARD_REPO,
    EXPECTED_RESPONSE_REPO,
    ROOT,
    _verify_checkout,
)

EXPECTED_BRANCH = "feature/response-diagnostic-expansion"
EXPECTED_VERSION = "1.1.0a1"


def _response_version() -> str:
    text = (ROOT / "backend" / "app" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None or match.group(1) != EXPECTED_VERSION:
        raise RuntimeError(
            f"Response alpha version must be {EXPECTED_VERSION}, found {match.group(1) if match else 'missing'}"
        )
    return match.group(1)


def _run(script: str, quietward: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / script),
            "--quietward-repo",
            str(quietward),
        ],
        cwd=ROOT,
        check=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete QuietWard Response v1.1.0-alpha.1 gates."
    )
    parser.add_argument("--quietward-repo", type=Path, required=True)
    args = parser.parse_args()

    quietward = args.quietward_repo.resolve()
    version = _response_version()
    response_head = _verify_checkout(
        ROOT,
        expected_branch=EXPECTED_BRANCH,
        expected_repo=EXPECTED_RESPONSE_REPO,
    )
    quietward_head = _verify_checkout(
        quietward,
        expected_branch=EXPECTED_BRANCH,
        expected_repo=EXPECTED_QUIETWARD_REPO,
    )

    _run("verify_v11_alpha.py", quietward)
    # Regression gate: the released v1 demo lifecycle must still work unchanged.
    _run("verify_v1_live.py", quietward)
    # New alpha gate: real QuietWard malware evidence -> approved read-only diagnostic.
    _run("verify_v11_alpha_live.py", quietward)

    print("\nQUIETWARD RESPONSE V1.1.0-ALPHA.1 AUTOMATED GATES: PASS")
    print(f"response_version={version}")
    print(f"response_head={response_head}")
    print(f"quietward_head={quietward_head}")
    print("Released v1 demo lifecycle regression: PASS")
    print("Expanded diagnostic lifecycle: PASS")
    print("QuietWard expanded detection suite: PASS")
    print("Both checkouts matched their exact pushed feature branches and contain origin/main.")
    print("Next: perform the documented browser UI smoke, then publish the alpha only if clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
