from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from app.models.event import Severity


IncidentStatus = Literal["new", "investigating", "contained", "resolved", "dismissed"]


class RecommendedAction(BaseModel):
    action_type: Literal["diagnostic", "remediation"]
    title: str
    description: str
    enabled: bool
    phase: str
    # v1 controlled-response metadata must survive FastAPI response-model
    # serialization so the analyst UI can distinguish executable allowlisted
    # recommendations from informational remediation guidance.
    registry_action_type: str | None = None
    requires_approval: bool = False


class TimelineEntry(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    summary: str
    severity: str
    evidence: dict[str, Any]


class AuditRead(BaseModel):
    audit_id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]


class IncidentSummary(BaseModel):
    incident_id: str
    title: str
    status: str
    severity: str
    confidence: float
    affected_hosts: list[str]
    created_at: datetime
    updated_at: datetime
    first_event_at: datetime
    last_event_at: datetime
    event_count: int
    probable_cause: str
    correlation_reasons: list[str]
    recommended_actions: list[RecommendedAction]


class IncidentDetail(IncidentSummary):
    timeline: list[TimelineEntry]
    events: list[dict[str, Any]]
    audit_trail: list[AuditRead]


class IncidentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus | None = None
    severity: Severity | None = None
