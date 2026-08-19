from __future__ import annotations

import json

from app import __version__
from scripts import promote_v1


def test_release_metadata_matches_current_v1_stage() -> None:
    """Catch stale RC/final version metadata in both qualification passes."""
    if __version__ == "1.0.0rc1":
        promote_v1._validate_release_markers()
        return

    assert __version__ == "1.0.0"
    package = json.loads(promote_v1.PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(promote_v1.PACKAGE_LOCK.read_text(encoding="utf-8"))
    root_package = (lock.get("packages") or {}).get("")
    assert package["version"] == "1.0.0"
    assert lock["version"] == "1.0.0"
    assert isinstance(root_package, dict) and root_package["version"] == "1.0.0"
    assert '"source_version": "1.0.0"' in promote_v1.SEED_DEMO.read_text(encoding="utf-8")
    assert "**Release status:** `v1.0.0` is the first public controlled-response release" in promote_v1.README.read_text(encoding="utf-8")
    assert "QuietWard Response v1 is local/trusted-network security software" in promote_v1.SECURITY.read_text(encoding="utf-8")
    changelog = promote_v1.CHANGELOG.read_text(encoding="utf-8")
    assert "## 1.0.0 — " in changelog
    assert "## 1.0.0-rc.1" not in changelog
