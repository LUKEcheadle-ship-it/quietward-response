"""Add audited human recovery workflows; no endpoint authority is added."""
from alembic import op
import sqlalchemy as sa

revision = "0004_guided_recovery"
down_revision = "0003_agent_diag_caps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resolution_workflows",
        sa.Column("workflow_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("host_id", sa.String(128), nullable=False),
        sa.Column("source_category", sa.String(32), nullable=False),
        sa.Column("family", sa.String(32), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("approver", sa.String(128), nullable=True),
        sa.Column("verifier", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("context_digest", sa.String(64), nullable=False),
        sa.Column("playbook_digest", sa.String(64), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("checkpoints", sa.JSON(), nullable=False),
        sa.Column("verification", sa.JSON(), nullable=True),
        sa.Column("escalation", sa.JSON(), nullable=True),
        sa.UniqueConstraint("incident_id", "host_id", "source_category", name="uq_resolution_scope"),
    )
    op.create_index("ix_resolution_workflows_incident_id", "resolution_workflows", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_resolution_workflows_incident_id", table_name="resolution_workflows")
    op.drop_table("resolution_workflows")
