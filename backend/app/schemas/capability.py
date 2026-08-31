from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AgentCapabilitiesReport(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: Literal["1.0"] = "1.0"
    agent_version: str = Field(min_length=1, max_length=64)
    supported_actions: list[str] = Field(default_factory=list, max_length=32)
    enabled_actions: list[str] = Field(default_factory=list, max_length=32)
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


class AgentCapabilityRead(BaseModel):
    agent_id: str
    agent_version: str
    supported_actions: list[str]
    enabled_actions: list[str]
    arbitrary_command_execution: bool
    updated_at: datetime
