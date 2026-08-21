"""Add signed Response-agent capability reporting and two-phase key-rotation state."""

from alembic import op
import sqlalchemy as sa

revision = "0003_agent_caps"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("supported_actions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "agents",
        sa.Column("enabled_actions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "agents",
        sa.Column("capabilities_updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_agents_capabilities_updated_at",
        "agents",
        ["capabilities_updated_at"],
        unique=False,
    )
    op.add_column("agents", sa.Column("pending_key_id", sa.String(length=64), nullable=True))
    op.add_column("agents", sa.Column("pending_hmac_key_b64", sa.String(length=256), nullable=True))
    op.add_column(
        "agents",
        sa.Column("pending_key_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("agents", sa.Column("previous_key_id", sa.String(length=64), nullable=True))
    op.add_column("agents", sa.Column("previous_hmac_key_b64", sa.String(length=256), nullable=True))
    op.add_column(
        "agents",
        sa.Column("previous_key_expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("agents", "previous_key_expires_at")
    op.drop_column("agents", "previous_hmac_key_b64")
    op.drop_column("agents", "previous_key_id")
    op.drop_column("agents", "pending_key_expires_at")
    op.drop_column("agents", "pending_hmac_key_b64")
    op.drop_column("agents", "pending_key_id")
    op.drop_index("ix_agents_capabilities_updated_at", table_name="agents")
    op.drop_column("agents", "capabilities_updated_at")
    op.drop_column("agents", "enabled_actions")
    op.drop_column("agents", "supported_actions")
