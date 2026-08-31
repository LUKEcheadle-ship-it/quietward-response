from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AgentCapabilityRecord(Base):
    """Signed capability declaration for one enrolled Response endpoint agent."""

    __tablename__ = "agent_capabilities"

    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"),
        primary_key=True,
    )
    agent_version: Mapped[str] = mapped_column(String(64))
    supported_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    enabled_actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    arbitrary_command_execution: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
