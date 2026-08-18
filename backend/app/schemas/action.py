from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ActionStatus = Literal[
    "pending",
    "approved",
    "rejected",
    "dispatching",
    "executing",
    "succeeded",
    "failed",
    "expired",
    "cancelled",
]


class ActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target_agent_id: str = Field(min_length=1, max_length=64)
    target_host_id: str = Field(min_length=1, max_length=128)
    action_type: str = Field(min_length=1, max_length=128)
    parameters: dict[str, Any] = Field(default_factory=dict)
    # None means use the server's QWR_ACTION_DEFAULT_TTL_SECONDS setting.
    expires_in_seconds: int | None = Field(default=None, ge=30, le=3600)


class ActionRead(BaseModel):
    schema_version: str
    action_id: str
    incident_id: str
    target_agent_id: str
    target_host_id: str
    action_type: str
    parameters: dict[str, Any]
    requested_at: datetime
    requested_by: str
    approval_id: str | None
    expires_at: datetime
    status: ActionStatus
    policy_allowed: bool | None
    policy_reasons: list[str]
    dispatched_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    result: dict[str, Any] | None
    error: str | None
    evidence: dict[str, Any] | None


class ApprovalDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    reason: str | None = Field(default=None, max_length=1024)


class ActionResultCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"] = "1.0"
    action_id: str = Field(min_length=1, max_length=36)
    agent_id: str = Field(min_length=1, max_length=64)
    host_id: str = Field(min_length=1, max_length=128)
    status: Literal["executing", "succeeded", "failed"]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=4096)
    evidence: dict[str, Any] = Field(default_factory=dict)
    agent_version: str | None = Field(default=None, max_length=64)

    @field_validator("started_at", "completed_at")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_lifecycle_timestamps(self) -> "ActionResultCreate":
        if self.status == "executing" and self.completed_at is not None:
            raise ValueError("executing result cannot include completed_at")
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at cannot be earlier than started_at")
        return self


class PolicyDecisionRead(BaseModel):
    allowed: bool
    reasons: list[str]
