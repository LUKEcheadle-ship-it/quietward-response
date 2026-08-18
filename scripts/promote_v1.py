#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND_VERSION_FILE = ROOT / "backend" / "app" / "__init__.py"
PACKAGE_JSON = ROOT / "frontend" / "package.json"
PACKAGE_LOCK = ROOT / "frontend" / "package-lock.json"
SEED_DEMO = ROOT / "scripts" / "seed_demo.py"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
SECURITY = ROOT / "SECURITY.md"

RC_BACKEND_VERSION = "1.0.0rc1"
FINAL_BACKEND_VERSION = "1.0.0"
FINAL_NPM_VERSION = "1.0.0"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path.relative_to(ROOT)}: expected exactly one release marker, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _promote_frontend_versions() -> None:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
    if package.get("name") != "quietward-response-frontend":
        raise RuntimeError("unexpected frontend package name")
    if lock.get("name") != package.get("name"):
        raise RuntimeError("frontend package-lock name does not match package.json")
    root_package = (lock.get("packages") or {}).get("")
    if not isinstance(root_package, dict) or root_package.get("name") != package.get("name"):
        raise RuntimeError("frontend package-lock root package is missing or inconsistent")

    package["version"] = FINAL_NPM_VERSION
    lock["version"] = FINAL_NPM_VERSION
    root_package["version"] = FINAL_NPM_VERSION
    _write_json(PACKAGE_JSON, package)
    _write_json(PACKAGE_LOCK, lock)


def main() -> int:
    branch = _git("branch", "--show-current")
    if branch != "feature/phase2-secure-integration":
        raise RuntimeError(
            "v1 promotion must run on feature/phase2-secure-integration before merge"
        )
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError("tracked working tree must be clean before v1 promotion")

    version_text = BACKEND_VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', version_text)
    if match is None or match.group(1) != RC_BACKEND_VERSION:
        raise RuntimeError(
            f"expected backend version {RC_BACKEND_VERSION!r} before promotion"
        )

    _replace_once(
        BACKEND_VERSION_FILE,
        '# Runtime/API version for the v1 release candidate. Promote to 1.0.0 only after\n# both automated v1 acceptance gates pass on a real checkout.\n__version__ = "1.0.0rc1"',
        '# Runtime/API version for the first public controlled-response release.\n__version__ = "1.0.0"',
    )
    _promote_frontend_versions()
    _replace_once(
        SEED_DEMO,
        '"source_version": "1.0.0rc1"',
        '"source_version": "1.0.0"',
    )
    _replace_once(
        README,
        '> **Release status:** the current development branch is `1.0.0rc1` until the documented automated and UI acceptance gates are executed successfully. The source is intentionally not labeled `1.0.0` before those gates pass.',
        '> **Release status:** `v1.0.0` is the first public controlled-response release. It remains intentionally narrow: authenticated telemetry, deterministic investigation/approval/policy, and one demo-fixture-only executable action.',
    )
    _replace_once(
        SECURITY,
        'QuietWard Response is pre-release security software. The v1 release candidate is designed for local or explicitly trusted-network incident investigation and controlled-response testing; it is not an Internet-facing production service.',
        'QuietWard Response v1 is local/trusted-network security software for incident investigation and controlled-response testing; it is not an Internet-facing production service.',
    )
    _replace_once(
        CHANGELOG,
        '## 1.0.0-rc.1 — 2026-08-18',
        '## 1.0.0 — 2026-08-18',
    )
    _replace_once(
        CHANGELOG,
        'Release-candidate implementation of the first end-to-end controlled-response system.',
        'First public release of the end-to-end controlled-response system.',
    )
    _replace_once(CHANGELOG, '### Release gate', '### Release qualification')
    _replace_once(
        CHANGELOG,
        'This revision remains a release candidate until both commands pass on a real checkout:',
        'Release qualification requires both commands to pass on a real checkout:',
    )
    _replace_once(
        CHANGELOG,
        'After those automated gates and the documented UI smoke check pass, promote the backend version from `1.0.0rc1` to `1.0.0` and merge the staged PRs.',
        'After promotion, rerun the complete release wrapper and the documented UI smoke check before merge, tag, or public-release publication.',
    )

    print("QUIETWARD RESPONSE VERSION PROMOTION: PREPARED")
    print("backend=1.0.0")
    print("frontend=1.0.0")
    print("public security/release docs=1.0.0")
    print("Next: review these deterministic version-only changes, commit them, then rerun scripts/finalize_v1.py before merge/tag/publication.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
