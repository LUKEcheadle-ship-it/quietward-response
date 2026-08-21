from __future__ import annotations

from app.schemas.action import ApprovalDecision
from app.services.redaction import REDACTED


def test_approval_reason_redacts_obvious_credentials_before_audit_persistence() -> None:
    decision = ApprovalDecision(
        reason="Approved after login password=swordfish Authorization: Bearer abcdefghijklmnop"
    )
    assert decision.reason is not None
    assert "swordfish" not in decision.reason
    assert "abcdefghijklmnop" not in decision.reason
    assert REDACTED in decision.reason
