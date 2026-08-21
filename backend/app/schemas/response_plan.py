from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


PlanPriority = Literal["routine", "elevated", "high", "critical"]
PlanStepState = Literal["available", "manual", "planned", "blocked"]


class ResponsePlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, max_length=96)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    state: PlanStepState
    destructive: bool = False
    requires_approval: bool = False
    executable_action_type: str | None = Field(default=None, max_length=128)


class ResponsePlanRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0", "1.1"] = "1.1"
    plan_id: str
    incident_id: str
    mode: Literal["advisory_with_controlled_actions"] = "advisory_with_controlled_actions"
    priority: PlanPriority
    attack_families: list[str]
    objectives: list[str]
    investigation_steps: list[ResponsePlanStep]
    containment_steps: list[ResponsePlanStep]
    recovery_steps: list[ResponsePlanStep]
    escalation_conditions: list[str]
    executable_actions: list[str]
    limitations: list[str]
