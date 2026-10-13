#!/usr/bin/env python3
"""Require all category definitions AND non-skipped executable recovery contracts."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.resolution_coverage import public_resolution_coverage, unresolved_categories
from app.services.resolution_playbooks import SOURCE_CATEGORIES


def main() -> int:
    coverage = public_resolution_coverage()
    print("QuietWard -> Response resolution coverage (human-executed, evidence-attested)", flush=True)
    for item in coverage:
        print(f"- {item['category']}: {'IMPLEMENTED' if item['release_ready'] else 'BLOCKED'} | {item['resolution_mode']} | {item['primary_outcome']}", flush=True)
    if unresolved_categories() or {str(c["category"]) for c in coverage} != set(SOURCE_CATEGORIES):
        print("GUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: BLOCKED — incomplete category definitions")
        return 1
    with tempfile.TemporaryDirectory(prefix="qwr-resolution-gate-") as temporary:
        junit = Path(temporary) / "contracts.xml"
        result = subprocess.run([sys.executable, "-m", "pytest", "tests/test_guided_recovery_workflows.py",
                                 "tests/test_resolution_coverage.py", "-W", "error", "-o", "addopts=", "-q",
                                 f"--junitxml={junit}"], cwd=BACKEND, check=False, timeout=240)
        if result.returncode != 0 or not junit.is_file():
            print("GUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: BLOCKED — executable contracts failed")
            return 1
        cases = ET.parse(junit).findall(".//testcase")
        if not cases or any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped")):
            print("GUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: BLOCKED — failed, skipped or absent checks")
            return 1
        names = {case.get("name") for case in cases}
        for category in SOURCE_CATEGORIES:
            for prefix in ("test_full_category_recovery_has_independent_evidence_and_audit", "test_category_escalation_requires_named_ack_and_does_not_claim_resolution"):
                if f"{prefix}[{category}]" not in names:
                    print(f"GUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: BLOCKED — missing {category} contract")
                    return 1
    print("GUIDED INCIDENT RESPONSE VNEXT RELEASE GATE: PASS — 12 category recovery and escalation contracts exercised")
    print("This qualifies workflow behavior, not automatic repair or server verification of external artifacts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
