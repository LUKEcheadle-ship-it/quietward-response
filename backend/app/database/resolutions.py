from __future__ import annotations

from datetime import datetime
from uuid import uuid4
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from .models import Base, utcnow


class ResolutionRecord(Base):
    __tablename__ = "resolution_workflows"
    __table_args__ = (UniqueConstraint("incident_id", "host_id", "source_category", name="uq_resolution_scope"),)

    workflow_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), index=True)
    host_id: Mapped[str] = mapped_column(String(128))
    source_category: Mapped[str] = mapped_column(String(32))
    family: Mapped[str] = mapped_column(String(32))
    state: Mapped[str] = mapped_column(String(32), default="awaiting_approval")
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    owner: Mapped[str] = mapped_column(String(128))
    approver: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verifier: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    context_digest: Mapped[str] = mapped_column(String(64))
    playbook_digest: Mapped[str] = mapped_column(String(64))
    plan: Mapped[dict] = mapped_column(JSON)
    checkpoints: Mapped[list] = mapped_column(JSON, default=list)
    verification: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    escalation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    __mapper_args__ = {"version_id_col": revision}
