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
    _run([python, "-m", "compileall", "-q", "scripts", "response_agent_resources.py"], cwd=ROOT)
    _run([python, str(ROOT / "scripts" / "audit_public_release.py")], cwd=ROOT)
    _run([python, "-m", "pytest", "-W", "error"], cwd=BACKEND)
    _run([python, str(ROOT / "scripts" / "verify_v12_surface.py")], cwd=ROOT)

    with tempfile.TemporaryDirectory(prefix="qwr-v12-alpha-") as temporary:
        temp_path = Path(temporary)
        _verify_fresh_migration(python, temp_path)
        _verify_phase1_upgrade(python, temp_path)

        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for the v1.2 alpha frontend gate")
        _run(_npm_command(npm, "ci"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "typecheck"), cwd=FRONTEND)
        _run(_npm_command(npm, "run", "build"), cwd=FRONTEND)
        _run(_npm_command(npm, "audit", "--audit-level=high"), cwd=FRONTEND)
        _verify_public_quick_start(python, temp_path)

    print("\nV1.2.0-ALPHA.1 STATIC/LOCAL GATE: PASS")
    print("Backend full pytest suite: PASS")
    print("Typed action/plan surface: PASS")
    print("Opaque-handle disposable containment: PASS")
    print("Analyst bearer authentication/RBAC: PASS")
    print("API request-size/rate bounds: PASS")
    print("Fresh and legacy migrations: PASS")
    print("Frontend typecheck/build/high-severity npm audit: PASS")
    print("Public quick-start and cleanup: PASS")
    print("Live standalone containment acceptance remains a separate required gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
