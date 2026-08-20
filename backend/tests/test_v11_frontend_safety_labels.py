from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_v11_ui_distinguishes_read_only_diagnostics_from_demo_mutation() -> None:
    text = (ROOT / "frontend" / "src" / "components" / "ResponseActions.tsx").read_text(
        encoding="utf-8"
    )
    assert "Read-only diagnostic · Approval required" in text
    assert "State-changing demo · Approval required" in text
    assert "Prepare read-only diagnostic" in text
    assert "The dedicated demo-fixture restart remains the only state-changing endpoint action" in text
    assert "arbitrary command execution is not available" in text
