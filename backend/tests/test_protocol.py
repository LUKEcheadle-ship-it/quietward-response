import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator, ValidationError

from app.integrations.quietward import QuietWardV1Integration

ROOT = Path(__file__).resolve().parents[2]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "protocol" / name).read_text(encoding="utf-8"))


def test_protocol_schema_is_valid_and_accepts_the_runtime_envelope(event_factory) -> None:
    schema = _schema("quietward-event-schema-v1.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(event_factory())


def test_protocol_and_integration_reject_unknown_top_level_fields(event_factory) -> None:
    schema = _schema("quietward-event-schema-v1.json")
    payload = event_factory()
    payload["command"] = "not-allowed"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(payload)
    with pytest.raises(ValueError):
        QuietWardV1Integration().parse(payload)


def test_action_protocol_accepts_full_server_dispatch_and_result_shapes() -> None:
    schema = _schema("quietward-action-schema-v1.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    now = datetime.now(timezone.utc).isoformat()
    action_id = str(uuid4())
    incident_id = str(uuid4())
    approval_id = str(uuid4())

    # Match the complete ActionRead shape emitted by FastAPI. Optional lifecycle
    # fields are still serialized as null and therefore belong in the wire schema.
    request = {
        "schema_version": "1.0",
        "action_id": action_id,
        "incident_id": incident_id,
        "target_agent_id": "agent-test",
        "target_host_id": "host-test",
        "action_type": "restart_quietward_demo_service",
        "parameters": {},
        "requested_at": now,
        "requested_by": "analyst",
        "approval_id": approval_id,
        "expires_at": now,
        "status": "executing",
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": now,
        "started_at": now,
        "completed_at": None,
        "result": {},
        "error": None,
        "evidence": {},
    }
    validator.validate(request)

    result = {
        "schema_version": "1.0",
        "action_id": action_id,
        "agent_id": "agent-test",
        "host_id": "host-test",
        "status": "succeeded",
        "started_at": now,
        "completed_at": now,
        "result": {"before": "unhealthy", "after": "running"},
        "error": None,
        "evidence": {"executor": "quietward-demo-fixture-v1"},
        "agent_version": "0.4.0a2",
    }
    validator.validate(result)


def test_action_protocol_has_no_generic_command_surface() -> None:
    schema = _schema("quietward-action-schema-v1.json")
    validator = Draft202012Validator(schema)
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "schema_version": "1.0",
        "action_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "target_agent_id": "agent-test",
        "target_host_id": "host-test",
        "action_type": "run_shell",
        "parameters": {"command": "whoami"},
        "requested_at": now,
        "requested_by": "analyst",
        "approval_id": str(uuid4()),
        "expires_at": now,
        "status": "approved",
        "policy_allowed": True,
        "policy_reasons": [],
    }
    with pytest.raises(ValidationError):
        validator.validate(payload)
