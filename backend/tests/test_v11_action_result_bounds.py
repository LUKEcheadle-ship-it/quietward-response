from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas.action import (
    MAX_ACTION_EVIDENCE_BYTES,
    MAX_ACTION_RESULT_BYTES,
    ActionResultCreate,
)


def _payload() -> dict:
    return {
        "schema_version": "1.0",
        "action_id": "00000000-0000-0000-0000-000000000001",
        "agent_id": "agent-test",
        "host_id": "host-test",
        "status": "succeeded",
        "result": {"ok": True},
        "evidence": {"executor": "test"},
        "agent_version": "test",
    }


def test_normal_action_result_is_accepted() -> None:
    value = ActionResultCreate.model_validate(_payload())
    assert value.result == {"ok": True}


def test_oversized_action_result_is_rejected_before_persistence() -> None:
    payload = _payload()
    payload["result"] = {"blob": "x" * (MAX_ACTION_RESULT_BYTES + 1024)}
    with pytest.raises(ValidationError, match="result exceeds"):
        ActionResultCreate.model_validate(payload)


def test_oversized_action_evidence_is_rejected_before_persistence() -> None:
    payload = _payload()
    payload["evidence"] = {"blob": "x" * (MAX_ACTION_EVIDENCE_BYTES + 1024)}
    with pytest.raises(ValidationError, match="evidence exceeds"):
        ActionResultCreate.model_validate(payload)
