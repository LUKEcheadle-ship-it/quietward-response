from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import __version__
from app.services.action_registry import ACTION_REGISTRY


EXPECTED_ACTIONS = {
    "restart_quietward_demo_service",
    "collect_host_diagnostic",
    "collect_process_diagnostic",
    "collect_network_diagnostic",
    "collect_incident_triage_bundle",
    "terminate_evidence_process",
}


def test_v11_preview_version_is_explicit() -> None:
    assert __version__ == "1.1.0a1"


def test_joint_handoff_uses_keyed_finding_identity_only() -> None:
    paths = [
        ROOT / "scripts" / "ingest_quietward_handoff.py",
        ROOT / "scripts" / "watch_quietward_handoffs.py",
        ROOT / "frontend" / "src" / "components" / "QuietWardContext.tsx",
    ]
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    assert "quietward_finding_id" not in text
    assert "quietward_finding_hmac_sha256" in text


def test_response_action_surface_is_exact_typed_and_has_no_generic_execution() -> None:
    assert set(ACTION_REGISTRY) == EXPECTED_ACTIONS
    paths = [
        ROOT / "scripts" / "response_agent.py",
        ROOT / "scripts" / "response_agent_diagnostics.py",
        ROOT / "scripts" / "incident_triage_bundle.py",
        ROOT / "scripts" / "evidence_store.py",
        ROOT / "scripts" / "process_containment.py",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    for forbidden in (
        "import subprocess",
        "from subprocess",
        "os.system(",
        "shell=true",
        "run_arbitrary_command",
        "terminate_arbitrary_process",
        "quarantine_arbitrary_path",
        "block_arbitrary_address",
    ):
        assert forbidden not in combined

    containment = ACTION_REGISTRY["terminate_evidence_process"]
    assert containment.approval_required is True
    assert containment.risk_level == "high"
    assert containment.reversible is False
    assert containment.validate_parameters({"pid": 1})
    assert containment.validate_parameters({"evidence_handle": "qwrp-" + "a" * 32}) == []


def test_agent_enrollment_uses_v11_candidate_version() -> None:
    enrollment = (ROOT / "scripts" / "enroll_response_agent.py").read_text(encoding="utf-8")
    assert 'AGENT_VERSION = "1.1.0a1"' in enrollment
    assert '"terminate_evidence_process"' in enrollment
