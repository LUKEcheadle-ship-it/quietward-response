from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.event import Severity


class EventCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"]
    event_id: UUID
    source: str = Field(min_length=1, max_length=128)
    source_version: str | None = Field(default=None, max_length=64)
    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    host_name: str | None = Field(default=None, max_length=255)
    timestamp: datetime
    event_type: str = Field(min_length=1, max_length=128)
    category: str | None = Field(default=None, max_length=128)
    severity: Severity
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=2048)
    evidence: dict[str, Any] = Field(default_factory=dict)
    process: dict[str, Any] | None = None
    file: dict[str, Any] | None = None
    network: dict[str, Any] | None = None
    persistence: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value


class EventRead(BaseModel):
    event_id: str
    schema_version: str
    source: str
    source_version: str | None
    host_id: str
    host_name: str
    timestamp: datetime
    event_type: str
    category: str | None
    severity: str
    confidence: float
    summary: str
    incident_id: str | None
    received_at: datetime
    evidence: dict[str, Any]
    process: dict[str, Any] | None
    file: dict[str, Any] | None
    network: dict[str, Any] | None
    persistence: dict[str, Any] | None
    metadata: dict[str, Any]


class IngestionResult(BaseModel):
    accepted: bool
    duplicate: bool = False
    event_id: str
    host_id: str
    incident_id: str
    correlation_reasons: list[str]
