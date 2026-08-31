"""Add signed Response-agent capability declarations."""

from alembic import op
import sqlalchemy as sa

revision = "0003_agent_diag_caps"
down_revision = "0002_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_capabilities",
        sa.Column(
            "agent_id",
            sa.String(length=64),
            sa.ForeignKey("agents.agent_id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("agent_version", sa.String(length=64), nullable=False),
        sa.Column(
            "supported_actions",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "enabled_actions",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column(
            "arbitrary_command_execution",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("agent_capabilities")
