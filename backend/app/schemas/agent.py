from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class AgentKeyRotationPrepareResponse(BaseModel):
    agent_id: str
    pending_key_id: str
    secret: str
    pending_key_expires_at: datetime


class AgentKeyRotationActivateResponse(BaseModel):
    agent_id: str
    key_id: str
    previous_key_revoked_at: datetime


class AgentCapabilitiesReport(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"] = "1.0"
    agent_version: str = Field(min_length=1, max_length=64)
    supported_actions: list[str] = Field(default_factory=list, max_length=32)
    enabled_actions: list[str] = Field(default_factory=list, max_length=32)
    resource_handle_protocol: Literal["qwrh1"] = "qwrh1"
    arbitrary_command_execution: Literal[False] = False

    @model_validator(mode="after")
    def validate_action_sets(self) -> "AgentCapabilitiesReport":
        if len(self.supported_actions) != len(set(self.supported_actions)):
            raise ValueError("supported_actions must not contain duplicates")
        if len(self.enabled_actions) != len(set(self.enabled_actions)):
            raise ValueError("enabled_actions must not contain duplicates")
        if not set(self.enabled_actions).issubset(set(self.supported_actions)):
            raise ValueError("enabled_actions must be a subset of supported_actions")
        for action_type in [*self.supported_actions, *self.enabled_actions]:
            if not action_type or len(action_type) > 128:
                raise ValueError("capability action names must be 1-128 characters")
        return self


class AgentRead(BaseModel):
    agent_id: str
    host_id: str
    display_name: str
    key_id: str
    created_at: datetime
    last_seen: datetime | None
    enabled: bool
    agent_version: str | None
    supported_actions: list[str] = Field(default_factory=list)
    enabled_actions: list[str] = Field(default_factory=list)
    capabilities_updated_at: datetime | None = None


class AgentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
