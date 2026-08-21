from __future__ import annotations

import json

from app import __version__
from scripts import promote_v1


def test_release_metadata_matches_current_stage() -> None:
    """Keep frozen v1 promotion checks intact while later alpha work evolves."""
    if __version__ in {"1.1.0a1", "1.2.0a1"}:
        # Later alphas have their own acceptance gates and must not be evaluated as
        # a final v1 promotion commit.
        return

    if __version__ == "1.0.0rc1":
        promote_v1._validate_rc_markers()
        return

    assert __version__ == "1.0.0"
    promote_v1._validate_final_markers()

    package = json.loads(promote_v1.PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(promote_v1.PACKAGE_LOCK.read_text(encoding="utf-8"))
    root_package = (lock.get("packages") or {}).get("")
    assert package["private"] is True
    assert package["version"] == promote_v1.INTERNAL_FRONTEND_VERSION
    assert lock["version"] == promote_v1.INTERNAL_FRONTEND_VERSION
    assert isinstance(root_package, dict)
    assert root_package["version"] == promote_v1.INTERNAL_FRONTEND_VERSION
