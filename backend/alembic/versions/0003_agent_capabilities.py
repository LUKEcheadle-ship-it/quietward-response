"""Add signed Response-agent capability reporting state."""

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


def downgrade() -> None:
    op.drop_index("ix_agents_capabilities_updated_at", table_name="agents")
    op.drop_column("agents", "capabilities_updated_at")
    op.drop_column("agents", "enabled_actions")
    op.drop_column("agents", "supported_actions")
