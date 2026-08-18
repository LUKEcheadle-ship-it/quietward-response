from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["new", "investigating", "contained", "resolved", "dismissed"] | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    status: str
    severity: str
    confidence: float
    affected_hosts: list
    created_at: datetime
    updated_at: datetime
    first_event_at: datetime
    last_event_at: datetime
    event_count: int
    probable_cause: str
    correlation_reasons: list
    recommended_actions: list


class TimelineItem(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    summary: str
    severity: str
    evidence: dict


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    audit_id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: str
    details: dict


class IncidentDetail(IncidentResponse):
    timeline: list[TimelineItem]
    events: list[dict]
    audit_trail: list[AuditResponse]
