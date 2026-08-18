from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.models import Base


class Host(Base):
    __tablename__ = "hosts"

    host_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    operating_system: Mapped[str | None] = mapped_column(String(100), nullable=True)
    agent: Mapped[str] = mapped_column(String(100))
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    status: Mapped[str] = mapped_column(String(30), default="reporting")

    events = relationship("Event", back_populates="host")
