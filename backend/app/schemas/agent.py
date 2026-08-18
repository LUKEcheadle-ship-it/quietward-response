from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AgentEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    display_name: str = Field(min_length=1, max_length=255)
    agent_version: str | None = Field(default=None, max_length=64)


class AgentEnrollResponse(BaseModel):
    agent_id: str
    key_id: str
    secret: str
    host_id: str
    created_at: datetime


class AgentRead(BaseModel):
    agent_id: str
    host_id: str
    display_name: str
    key_id: str
    created_at: datetime
    last_seen: datetime | None
    enabled: bool
    agent_version: str | None


class AgentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
