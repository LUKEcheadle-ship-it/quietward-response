from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.models import Base


class AgentPublicCredentialRecord(Base):
    """v1.3 prototype storage for public endpoint verification material only."""

    __tablename__ = "agent_public_credentials"
    __table_args__ = (
        UniqueConstraint("key_id", name="uq_agent_public_credentials_key_id"),
        Index(
            "ix_agent_public_credentials_agent_status",
            "agent_id",
            "status",
        ),
    )

    credential_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.agent_id", ondelete="CASCADE"),
        index=True,
    )
    key_id: Mapped[str] = mapped_column(String(39))
    algorithm: Mapped[str] = mapped_column(String(32), default="Ed25519")
    protocol_version: Mapped[str] = mapped_column(
        String(64),
        default="qwr-agent-signature-v1",
    )
    public_key_b64: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
