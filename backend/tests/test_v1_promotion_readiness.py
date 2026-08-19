from __future__ import annotations

from scripts import promote_v1


def test_rc_source_is_deterministically_promotion_ready() -> None:
    """Catch stale release markers/package metadata before the RC is qualified."""
    promote_v1._validate_release_markers()
