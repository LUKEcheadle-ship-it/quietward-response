"""Add isolated v1.3 public-key agent credential lifecycle storage.

This migration is carried only on the v1.3 prototype branch. It does not switch the
live v1.2 HMAC authentication path. The table intentionally contains public
verification material and lifecycle metadata only; no endpoint private key or
symmetric signing secret belongs here.
"""

from alembic import op
import sqlalchemy as sa

revision = "0004_agent_public_credentials"
down_revision = "0003_agent_caps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_public_credentials",
        sa.Column("credential_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column(
            "agent_id",
            sa.String(length=64),
            sa.ForeignKey("agents.agent_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("key_id", sa.String(length=39), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("protocol_version", sa.String(length=64), nullable=False),
        sa.Column("public_key_b64", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("key_id", name="uq_agent_public_credentials_key_id"),
    )
    op.create_index(
        "ix_agent_public_credentials_agent_status",
        "agent_public_credentials",
        ["agent_id", "status"],
        unique=False,
    )
    # At most one active public-key credential per agent. PostgreSQL can enforce a
    # partial unique index directly; SQLite test/runtime compatibility is handled
    # by application transactional checks until the v1.3 storage service is enabled.


def downgrade() -> None:
    op.drop_index(
        "ix_agent_public_credentials_agent_status",
        table_name="agent_public_credentials",
    )
    op.drop_table("agent_public_credentials")
