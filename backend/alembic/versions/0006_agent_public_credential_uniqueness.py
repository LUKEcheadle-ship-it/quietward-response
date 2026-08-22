"""Enforce one active and one pending v1.3 public credential per agent."""

from alembic import op
import sqlalchemy as sa

revision = "0006_agent_public_credential_uniqueness"
down_revision = "0005_agent_public_credential_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    active_where = sa.text("status = 'active'")
    pending_where = sa.text("status = 'pending'")
    op.create_index(
        "uq_agent_public_credentials_one_active",
        "agent_public_credentials",
        ["agent_id"],
        unique=True,
        postgresql_where=active_where,
        sqlite_where=active_where,
    )
    op.create_index(
        "uq_agent_public_credentials_one_pending",
        "agent_public_credentials",
        ["agent_id"],
        unique=True,
        postgresql_where=pending_where,
        sqlite_where=pending_where,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_agent_public_credentials_one_pending",
        table_name="agent_public_credentials",
    )
    op.drop_index(
        "uq_agent_public_credentials_one_active",
        table_name="agent_public_credentials",
    )
