#!/usr/bin/env python3
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from verify_v1 import (
    BACKEND,
    FRONTEND,
    ROOT,
    _ensure_python,
    _npm_command,
    _run,
    _verify_fresh_migration,
    _verify_phase1_upgrade,
    _verify_public_quick_start,
)


def main() -> int:
    python = _ensure_python()

    _run([python, "-m", "compileall", "-q", "app", "tests"], cwd=BACKEND)
    _run([python, "-m", "compileall", "-q", "scripts"], cwd=ROOT)
    _run([python, str(ROOT / "scripts" / "audit_public_release.py")], cwd=ROOT)
    _run([python, "-m", "pytest", "-W", "error"], cwd=BACKEND)
    _run([python, str(ROOT / "scripts" / "verify_v11_diagnostics.py")], cwd=ROOT)

    with tempfile.TemporaryDirectory(prefix="qwr-v11-alpha-") as temporary:
        temp_path = Path(temporary)
        _verify_fresh_migration(python, temp_path)
        _verify_phase1_upgrade(python, temp_path)

        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for the v1.1 alpha frontend gate")
        _run(_npm_command(npm, "ci"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "typecheck"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "build"), cwd=FRONTEND)
        _run(_npm_command(npm, "audit", "--audit-level=high"), cwd=FRONTEND)
        _verify_public_quick_start(python, temp_path)

    print("\nV1.1.0-ALPHA.1 STATIC/LOCAL GATE: PASS")
    print("Response backend tests: PASS")
    print("Standalone response-plan surface: PASS")
    print("Executable action surface remains demo-only: PASS")
    print("Fresh and legacy migrations: PASS")
    print("Frontend typecheck/build/high-severity audit: PASS")
    print("Public quick-start and cleanup: PASS")
    print("No companion detector repository is required by this gate.")
    print("Live standalone HTTP response-plan acceptance remains a separate required gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
