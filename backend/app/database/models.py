from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class HostRecord(Base):
    __tablename__ = "hosts"

    host_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    operating_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent: Mapped[str] = mapped_column(String(128))
    agent_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(32), default="reporting")

    events: Mapped[list[EventRecord]] = relationship(back_populates="host")


class IncidentRecord(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    affected_hosts: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    probable_cause: Mapped[str] = mapped_column(Text, default="Assessment pending")
    correlation_reasons: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommended_actions: Mapped[list[dict[str, object]]] = mapped_column(JSON, default=list)

    events: Mapped[list[EventRecord]] = relationship(back_populates="incident")
    audits: Mapped[list[AuditRecord]] = relationship(back_populates="incident")


class EventRecord(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_host_time", "host_id", "occurred_at"),
        Index("ix_events_type_time", "event_type", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(128), index=True)
    source_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.host_id"), index=True)
    host_name: Mapped[str] = mapped_column(String(255))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    summary: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, object]] = mapped_column(JSON)
    normalized: Mapped[dict[str, object]] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id"), nullable=True, index=True
    )

    host: Mapped[HostRecord] = relationship(back_populates="events")
    incident: Mapped[IncidentRecord | None] = relationship(back_populates="events")


class AuditRecord(Base):
    __tablename__ = "audit_records"
    __table_args__ = (Index("ix_audit_resource", "resource_type", "resource_id"),)

    audit_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor_type: Mapped[str] = mapped_column(String(64))
    actor_id: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    resource_id: Mapped[str] = mapped_column(String(128), index=True)
    details: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    incident_id: Mapped[str | None] = mapped_column(
        ForeignKey("incidents.incident_id"), nullable=True, index=True
    )

    incident: Mapped[IncidentRecord | None] = relationship(back_populates="audits")
