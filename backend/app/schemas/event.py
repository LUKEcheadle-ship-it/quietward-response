from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    event_id: UUID
    source: str = Field(min_length=1, max_length=100)
    source_version: str | None = Field(default=None, max_length=50)
    host_id: str = Field(min_length=1, max_length=255)
    host_name: str | None = Field(default=None, max_length=255)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=100)
    category: str | None = Field(default=None, max_length=100)
    severity: Severity
    confidence: int = Field(default=50, ge=0, le=100)
    summary: str = Field(min_length=1, max_length=1000)
    evidence: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] = Field(default_factory=dict)
    file: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    persistence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone offset")
        return value


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    schema_version: str
    source: str
    source_version: str | None
    host_id: str
    host_name: str | None
    timestamp: datetime
    event_type: str
    category: str | None
    severity: str
    confidence: int
    summary: str
    evidence: dict
    process: dict
    file: dict
    network: dict
    persistence: dict
    metadata: dict
    incident_id: str | None
    received_at: datetime


class IngestionResult(BaseModel):
    status: Literal["accepted"] = "accepted"
    event_id: str
    host_id: str
    incident_id: str
    incident_created: bool
    correlation_reasons: list[str]
