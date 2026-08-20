#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any

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
# The Next.js package is private implementation metadata rather than a published
# artifact. Keep package.json/package-lock.json on their internal app version while
# the product/API release is versioned independently as v1.0.0.
INTERNAL_FRONTEND_VERSION = "0.1.0"

BACKEND_RC_MARKER = (
    '# Runtime/API version for the v1 release candidate. Promote to 1.0.0 only after\n'
    '# both automated v1 acceptance gates pass on a real checkout.\n'
    '__version__ = "1.0.0rc1"'
)
BACKEND_FINAL_MARKER = (
    '# Runtime/API version for the first public controlled-response release.\n'
    '__version__ = "1.0.0"'
)
README_RC_MARKER = (
    '> **Release status:** the current development branch is `1.0.0rc1` until the '
    'documented automated and UI acceptance gates are executed successfully. The '
    'source is intentionally not labeled `1.0.0` before those gates pass.'
)
README_FINAL_MARKER = (
    '> **Release status:** `v1.0.0` is the first public controlled-response release. '
    'It remains intentionally narrow: authenticated telemetry, deterministic '
    'investigation/approval/policy, and one demo-fixture-only executable action.'
)
SECURITY_RC_MARKER = (
    'QuietWard Response is pre-release security software. The v1 release candidate '
    'is designed for local or explicitly trusted-network incident investigation and '
    'controlled-response testing; it is not an Internet-facing production service.'
)
SECURITY_FINAL_MARKER = (
    'QuietWard Response v1 is local/trusted-network security software for incident '
    'investigation and controlled-response testing; it is not an Internet-facing '
    'production service.'
)
CHANGELOG_RC_DESCRIPTION = (
    'Release-candidate implementation of the first end-to-end controlled-response system.'
)
CHANGELOG_GATE_TEXT = (
    'This revision remains a release candidate until both commands pass on a real checkout:'
)
CHANGELOG_PROMOTION_TEXT = (
    'After those automated gates and the documented UI smoke check pass, promote the '
    'backend version from `1.0.0rc1` to `1.0.0` and merge the staged PRs.'
)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _assert_once(path: Path, marker: str) -> None:
    count = path.read_text(encoding="utf-8").count(marker)
    if count != 1:
        raise RuntimeError(
            f"{path.relative_to(ROOT)}: expected exactly one release marker, found {count}"
        )


def _assert_regex_once(path: Path, pattern: str) -> None:
    matches = re.findall(pattern, path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError(
            f"{path.relative_to(ROOT)}: expected exactly one release marker, found {len(matches)}"
        )


def _replace_once(path: Path, old: str, new: str) -> None:
    _assert_once(path, old)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _replace_regex_once(path: Path, pattern: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(
            f"{path.relative_to(ROOT)}: expected exactly one release marker, found {count}"
        )
    path.write_text(updated, encoding="utf-8")


def _frontend_documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
    if package.get("name") != "quietward-response-frontend":
        raise RuntimeError("unexpected frontend package name")
    if package.get("private") is not True:
        raise RuntimeError("frontend package must remain private")
    if lock.get("name") != package.get("name"):
        raise RuntimeError("frontend package-lock name does not match package.json")
    root_package = (lock.get("packages") or {}).get("")
    if not isinstance(root_package, dict) or root_package.get("name") != package.get("name"):
        raise RuntimeError("frontend package-lock root package is missing or inconsistent")
    versions = {package.get("version"), lock.get("version"), root_package.get("version")}
    if versions != {INTERNAL_FRONTEND_VERSION}:
        raise RuntimeError(
            "private frontend package/package-lock versions must remain internally consistent at "
            f"{INTERNAL_FRONTEND_VERSION}"
        )
    return package, lock, root_package


def _backend_version() -> str:
    text = BACKEND_VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if match is None:
        raise RuntimeError("backend version marker is missing")
    return match.group(1)


def _validate_rc_markers() -> None:
    if _backend_version() != RC_BACKEND_VERSION:
        raise RuntimeError(f"expected backend version {RC_BACKEND_VERSION!r} before promotion")
    _assert_once(BACKEND_VERSION_FILE, BACKEND_RC_MARKER)
    _frontend_documents()
    _assert_once(SEED_DEMO, '"source_version": "1.0.0rc1"')
    _assert_once(README, README_RC_MARKER)
    _assert_once(SECURITY, SECURITY_RC_MARKER)
    _assert_regex_once(CHANGELOG, r'^## 1\.0\.0-rc\.1 — \d{4}-\d{2}-\d{2}$')
    _assert_once(CHANGELOG, CHANGELOG_RC_DESCRIPTION)
    _assert_once(CHANGELOG, '### Release gate')
    _assert_once(CHANGELOG, CHANGELOG_GATE_TEXT)
    _assert_once(CHANGELOG, CHANGELOG_PROMOTION_TEXT)


def _validate_final_markers() -> None:
    if _backend_version() != FINAL_BACKEND_VERSION:
        raise RuntimeError(f"expected final backend version {FINAL_BACKEND_VERSION!r}")
    _assert_once(BACKEND_VERSION_FILE, BACKEND_FINAL_MARKER)
    _frontend_documents()
    _assert_once(SEED_DEMO, '"source_version": "1.0.0"')
    _assert_once(README, README_FINAL_MARKER)
    _assert_once(SECURITY, SECURITY_FINAL_MARKER)
    _assert_regex_once(CHANGELOG, r'^## 1\.0\.0 — \d{4}-\d{2}-\d{2}$')
    if "## 1.0.0-rc.1" in CHANGELOG.read_text(encoding="utf-8"):
        raise RuntimeError("final changelog still contains the RC heading")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate or prepare QuietWard Response v1 RC-to-final promotion."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate release metadata without modifying files.",
    )
    args = parser.parse_args()

    branch = _git("branch", "--show-current")
    if branch != "feature/phase2-secure-integration":
        raise RuntimeError(
            "v1 promotion must run on feature/phase2-secure-integration before merge"
        )
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise RuntimeError("tracked working tree must be clean before v1 promotion")

    version = _backend_version()
    if version == FINAL_BACKEND_VERSION:
        _validate_final_markers()
        print("QUIETWARD RESPONSE VERSION PROMOTION CHECK: PASS")
        print("Product/API release metadata is already final at v1.0.0.")
        print(f"Private frontend package metadata remains {INTERNAL_FRONTEND_VERSION} by design.")
        return 0

    _validate_rc_markers()
    if args.check:
        print("QUIETWARD RESPONSE VERSION PROMOTION CHECK: PASS")
        print("All RC markers are promotion-ready.")
        print(f"Private frontend package metadata remains {INTERNAL_FRONTEND_VERSION} by design.")
        return 0

    release_date = date.today().isoformat()
    _replace_once(BACKEND_VERSION_FILE, BACKEND_RC_MARKER, BACKEND_FINAL_MARKER)
    _replace_once(SEED_DEMO, '"source_version": "1.0.0rc1"', '"source_version": "1.0.0"')
    _replace_once(README, README_RC_MARKER, README_FINAL_MARKER)
    _replace_once(SECURITY, SECURITY_RC_MARKER, SECURITY_FINAL_MARKER)
    _replace_regex_once(
        CHANGELOG,
        r'^## 1\.0\.0-rc\.1 — \d{4}-\d{2}-\d{2}$',
        f'## 1.0.0 — {release_date}',
    )
    _replace_once(
        CHANGELOG,
        CHANGELOG_RC_DESCRIPTION,
        'First public release of the end-to-end controlled-response system.',
    )
    _replace_once(CHANGELOG, '### Release gate', '### Release qualification')
    _replace_once(
        CHANGELOG,
        CHANGELOG_GATE_TEXT,
        'Release qualification requires both commands to pass on a real checkout:',
    )
    _replace_once(
        CHANGELOG,
        CHANGELOG_PROMOTION_TEXT,
        'The final `1.0.0` commit must pass the complete wrapper and the documented UI '
        'smoke check before merge, tag, or public-release publication.',
    )

    _validate_final_markers()
    print("QUIETWARD RESPONSE VERSION PROMOTION: PREPARED")
    print("backend=1.0.0")
    print(f"frontend_internal={INTERNAL_FRONTEND_VERSION}")
    print(f"release_date={release_date}")
    print("public security/release docs=1.0.0")
    print("Next: commit these deterministic release metadata changes and rerun the full release gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
