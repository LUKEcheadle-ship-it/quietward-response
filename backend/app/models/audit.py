from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class Audit(Base):
    __tablename__ = "audits"

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor_type: Mapped[str] = mapped_column(String(50))
    actor_id: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(50), index=True)
    resource_id: Mapped[str] = mapped_column(String(255), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
