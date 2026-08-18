from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.models import Base


class Event(Base):
    __tablename__ = "events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(10))
    source: Mapped[str] = mapped_column(String(100), index=True)
    source_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.host_id"), index=True)
    host_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    category: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    process: Mapped[dict] = mapped_column(JSON, default=dict)
    file: Mapped[dict] = mapped_column(JSON, default=dict)
    network: Mapped[dict] = mapped_column(JSON, default=dict)
    persistence: Mapped[dict] = mapped_column(JSON, default=dict)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.incident_id"), nullable=True, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    host = relationship("Host", back_populates="events")
    incident = relationship("Incident", back_populates="events")
