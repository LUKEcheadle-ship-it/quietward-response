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


def _action_request(action_type: str, parameters: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": "1.0",
        "action_id": str(uuid4()),
        "incident_id": str(uuid4()),
        "target_agent_id": "agent-test",
        "target_host_id": "host-test",
        "action_type": action_type,
        "parameters": parameters,
        "requested_at": now,
        "requested_by": "analyst",
        "approval_id": str(uuid4()),
        "expires_at": now,
        "status": "dispatching",
        "policy_allowed": True,
        "policy_reasons": [],
        "dispatched_at": now,
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None,
        "evidence": None,
    }


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
    request = _action_request("restart_quietward_demo_service", {})
    validator.validate(request)

    now = datetime.now(timezone.utc).isoformat()
    result = {
        "schema_version": "1.0",
        "action_id": request["action_id"],
        "agent_id": "agent-test",
        "host_id": "host-test",
        "status": "succeeded",
        "started_at": now,
        "completed_at": now,
        "result": {"before": "unhealthy", "after": "running"},
        "error": None,
        "evidence": {"executor": "quietward-demo-fixture-v1"},
        "agent_version": "1.1.0a1",
    }
    validator.validate(result)


def test_process_containment_protocol_requires_opaque_evidence_handle() -> None:
    schema = _schema("quietward-action-schema-v1.json")
    validator = Draft202012Validator(schema)

    valid = _action_request(
        "terminate_evidence_process",
        {"evidence_handle": "qwrp-" + "a" * 32},
    )
    validator.validate(valid)

    arbitrary_pid = _action_request("terminate_evidence_process", {"pid": 4242})
    with pytest.raises(ValidationError):
        validator.validate(arbitrary_pid)

    malformed_handle = _action_request(
        "terminate_evidence_process",
        {"evidence_handle": "qwrp-not-valid"},
    )
    with pytest.raises(ValidationError):
        validator.validate(malformed_handle)

    extra_target = _action_request(
        "terminate_evidence_process",
        {"evidence_handle": "qwrp-" + "a" * 32, "pid": 4242},
    )
    with pytest.raises(ValidationError):
        validator.validate(extra_target)


def test_action_protocol_has_no_generic_command_surface() -> None:
    schema = _schema("quietward-action-schema-v1.json")
    validator = Draft202012Validator(schema)
    payload = _action_request("run_shell", {"command": "whoami"})
    with pytest.raises(ValidationError):
        validator.validate(payload)
