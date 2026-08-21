from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "docs" / "V12_ADVERSARIAL_REGRESSION_MATRIX.md"


def test_adversarial_matrix_contains_critical_v12_failure_modes() -> None:
    text = MATRIX.read_text(encoding="utf-8")
    required_ids = {
        "AUTH-01",
        "CAP-01",
        "CAP-07",
        "KEY-03",
        "KEY-08",
        "HANDLE-03",
        "PROCESS-01",
        "FILE-01",
        "TRUST-01",
        "DATA-01",
        "DATA-05",
        "API-02",
        "AUDIT-02",
        "AUDIT-06",
        "UI-02",
        "CMD-01",
    }
    for case_id in required_ids:
        assert f"| {case_id} |" in text

    lower = text.lower()
    assert "a test file existing in github is not itself a qualification result" in lower
    assert "no case permits testing against arbitrary non-test-owned processes/files" in lower
    assert "generic shell execution" in lower


def test_explicitly_mapped_test_files_in_adversarial_matrix_exist() -> None:
    text = MATRIX.read_text(encoding="utf-8")
    names = set(re.findall(r"`(test_v12_[a-z0-9_]+\.py)`", text))
    assert names, "matrix should explicitly map v1.2 cases to regression files"
    missing = [name for name in sorted(names) if not (ROOT / "backend" / "tests" / name).exists()]
    assert missing == []


def test_matrix_does_not_claim_unimplemented_mutation_families_are_qualified() -> None:
    text = MATRIX.read_text(encoding="utf-8").lower()
    assert "no case authorizes" in text
    for capability in (
        "firewall changes",
        "account mutation",
        "container mutation",
        "host isolation",
    ):
        assert capability in text
