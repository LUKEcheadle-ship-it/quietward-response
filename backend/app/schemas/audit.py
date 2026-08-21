from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuditCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    generated_at: datetime
    entries_checked: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("generated_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("checkpoint timestamp must include a timezone")
        return value


class AuditCheckpointVerification(BaseModel):
    valid: bool
    signature_valid: bool
    prefix_valid: bool
    current_chain_valid: bool
    checkpoint_entries: int | None = None
    current_entries: int | None = None
    checkpoint_head_hash: str | None = None
    current_head_hash: str | None = None
    error: str | None = None
