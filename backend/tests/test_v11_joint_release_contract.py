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


def test_response_action_surface_remains_bounded_and_non_destructive() -> None:
    assert set(ACTION_REGISTRY) == EXPECTED_ACTIONS
    executor = (ROOT / "scripts" / "response_agent.py").read_text(encoding="utf-8").lower()
    diagnostics = (ROOT / "scripts" / "response_agent_diagnostics.py").read_text(encoding="utf-8").lower()
    combined = executor + "\n" + diagnostics
    for forbidden in (
        "import subprocess",
        "from subprocess",
        "os.system(",
        "shell=true",
        "terminate_process_by_handle",
        "quarantine_artifact_by_handle",
        "restore_quarantined_artifact_by_handle",
        "block_network",
        "isolate_host",
    ):
        assert forbidden not in combined


def test_agent_enrollment_uses_v11_candidate_version() -> None:
    enrollment = (ROOT / "scripts" / "enroll_response_agent.py").read_text(encoding="utf-8")
    assert 'AGENT_VERSION = "1.1.0a1"' in enrollment
