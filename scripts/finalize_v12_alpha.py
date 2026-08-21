#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from finalize_v1 import EXPECTED_RESPONSE_REPO, ROOT, _verify_checkout

EXPECTED_BRANCH = "feature/response-v12-hardening"
EXPECTED_VERSION = "1.2.0a1"


def _response_version() -> str:
    text = (ROOT / "backend" / "app" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None or match.group(1) != EXPECTED_VERSION:
        raise RuntimeError(
            f"Response v1.2 alpha version must be {EXPECTED_VERSION}, "
            f"found {match.group(1) if match else 'missing'}"
        )
    return match.group(1)


def _run(script: str) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / script)],
        cwd=ROOT,
        check=True,
    )


def main() -> int:
    version = _response_version()
    response_head = _verify_checkout(
        ROOT,
        expected_branch=EXPECTED_BRANCH,
        expected_repo=EXPECTED_RESPONSE_REPO,
    )

    _run("verify_v12_alpha.py")
    _run("verify_v12_alpha_live_capabilities.py")

    print("\nQUIETWARD RESPONSE V1.2.0-ALPHA.1 AUTOMATED GATES: PASS")
    print(f"response_version={version}")
    print(f"response_head={response_head}")
    print("Full backend/static/local qualification: PASS")
    print("Fresh + Phase 1 upgrade migration qualification to 0003_agent_caps: PASS")
    print("Signed agent capability negotiation: PASS")
    print("Two-phase crash-recoverable agent key rotation: PASS")
    print("Live handle-bound quarantine/restore: PASS")
    print("Live disposable exact-process termination: PASS")
    print("Analyst bearer RBAC and authenticated audit identity: PASS")
    print("Signed externalizable audit checkpoints: PASS")
    print("API request-size/rate bounds: PASS")
    print("Raw PID/path and generic command targeting remain unavailable: PASS")
    print("No detector repository checkout is required or modified by this finalizer.")
    print("Next: perform the documented browser UI smoke on this exact candidate SHA.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
