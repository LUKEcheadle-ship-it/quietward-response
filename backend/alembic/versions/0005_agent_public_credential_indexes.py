"""Align v1.3 public-credential indexes with the prototype ORM model."""

from alembic import op

revision = "0005_agent_public_credential_indexes"
down_revision = "0004_agent_public_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_agent_public_credentials_agent_id",
        "agent_public_credentials",
        ["agent_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_public_credentials_status",
        "agent_public_credentials",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_public_credentials_status",
        table_name="agent_public_credentials",
    )
    op.drop_index(
        "ix_agent_public_credentials_agent_id",
        table_name="agent_public_credentials",
    )
