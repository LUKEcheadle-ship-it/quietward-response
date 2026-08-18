import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from app.integrations.quietward import QuietWardV1Integration

ROOT = Path(__file__).resolve().parents[2]


def test_protocol_schema_is_valid_and_accepts_the_runtime_envelope(event_factory) -> None:
    schema = json.loads(
        (ROOT / "protocol" / "quietward-event-schema-v1.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(event_factory())


def test_protocol_and_integration_reject_unknown_top_level_fields(event_factory) -> None:
    schema = json.loads(
        (ROOT / "protocol" / "quietward-event-schema-v1.json").read_text(encoding="utf-8")
    )
    payload = event_factory()
    payload["command"] = "not-allowed"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(payload)
    with pytest.raises(ValueError):
        QuietWardV1Integration().parse(payload)
