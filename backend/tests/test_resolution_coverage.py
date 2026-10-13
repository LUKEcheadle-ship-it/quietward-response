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


def test_every_declared_category_has_a_concrete_tested_recovery_contract() -> None:
    from app.services.resolution_playbooks import PLAYBOOKS, SOURCE_CATEGORIES
    assert set(SOURCE_CATEGORIES) == EXPECTED_QUIETWARD_CATEGORIES
    assert set(PLAYBOOKS) == EXPECTED_QUIETWARD_CATEGORIES - {"security"}
    assert unresolved_categories() == []
    for coverage in RESOLUTION_COVERAGE.values():
        assert coverage.resolution_mode in {"guided_human_recovery", "evidence_routed_guided_recovery"}


def test_unimplemented_automatic_recommendations_point_to_guided_recovery() -> None:
    from types import SimpleNamespace
    from app.services.recommendation import recommendations_for
    for category in ("persistence", "network", "operational", "identity"):
        event = SimpleNamespace(category=category, event_type="review_test", raw_payload={})
        actions = recommendations_for([event])
        disabled = [a for a in actions if a["action_type"] == "remediation" and not a["enabled"]]
        assert disabled, category
        for action in disabled:
            assert "Guided resolution" in action["description"]
            assert action["registry_action_type"] is None
            assert "release-blocking" not in action["description"]
