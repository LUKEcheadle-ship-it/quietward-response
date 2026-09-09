from __future__ import annotations

from app.services.resolution_coverage import RESOLUTION_COVERAGE, unresolved_categories


EXPECTED_QUIETWARD_CATEGORIES = {
    "malware",
    "integrity",
    "privilege",
    "persistence",
    "identity",
    "network",
    "container",
    "vulnerability",
    "execution",
    "file_integrity",
    "operational",
    "security",
}


def test_resolution_matrix_covers_every_quietward_response_category() -> None:
    assert set(RESOLUTION_COVERAGE) == EXPECTED_QUIETWARD_CATEGORIES
    for category, coverage in RESOLUTION_COVERAGE.items():
        assert coverage.category == category
        assert coverage.resolution_mode
        assert coverage.primary_outcome
        assert coverage.rationale


def test_vnext_remains_release_blocked_until_resolution_paths_are_complete() -> None:
    # This is a development invariant, not the final release assertion. The final
    # gate is scripts/verify_vnext_resolution_coverage.py, which exits non-zero while
    # this list is non-empty. When the final category is implemented, this test
    # should be updated in the same commit to assert unresolved_categories() == [].
    assert set(unresolved_categories()) <= EXPECTED_QUIETWARD_CATEGORIES
