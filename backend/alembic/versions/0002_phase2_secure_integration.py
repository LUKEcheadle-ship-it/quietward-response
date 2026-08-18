"""Add v1 authenticated agents, approvals, actions, replay nonces, and audit hashes."""

from alembic import op
import sqlalchemy as sa

revision = "0002_phase2"
down_revision = "0001_phase1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("host_id", sa.String(length=128), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("hmac_key_b64", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.UniqueConstraint("key_id", name="uq_agents_key_id"),
    )
    op.create_index("ix_agents_host_id", "agents", ["host_id"], unique=False)
    op.create_index("ix_agents_key_id", "agents", ["key_id"], unique=True)
    op.create_index("ix_agents_last_seen", "agents", ["last_seen"], unique=False)
    op.create_index("ix_agents_enabled", "agents", ["enabled"], unique=False)

    op.create_table(
        "agent_nonces",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column("agent_id", sa.String(length=64), sa.ForeignKey("agents.agent_id"), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("agent_id", "nonce", name="uq_agent_nonce"),
    )
    op.create_index("ix_agent_nonces_agent_id", "agent_nonces", ["agent_id"], unique=False)
    op.create_index("ix_agent_nonce_timestamp", "agent_nonces", ["timestamp"], unique=False)

    op.create_table(
        "approvals",
        sa.Column("approval_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("action_id", sa.String(length=36), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("action_id", name="uq_approvals_action_id"),
    )
    op.create_index("ix_approvals_incident_id", "approvals", ["incident_id"], unique=False)
    op.create_index("ix_approvals_action_id", "approvals", ["action_id"], unique=True)
    op.create_index("ix_approvals_status", "approvals", ["status"], unique=False)
    op.create_index("ix_approvals_expires_at", "approvals", ["expires_at"], unique=False)

    op.create_table(
        "actions",
        sa.Column("action_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.incident_id"), nullable=False),
        sa.Column("target_agent_id", sa.String(length=64), sa.ForeignKey("agents.agent_id"), nullable=False),
        sa.Column("target_host_id", sa.String(length=128), nullable=False),
        sa.Column("action_type", sa.String(length=128), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("approval_id", sa.String(length=36), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("policy_allowed", sa.Boolean(), nullable=True),
        sa.Column("policy_reasons", sa.JSON(), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
    )
    op.create_index("ix_actions_incident_id", "actions", ["incident_id"], unique=False)
    op.create_index("ix_actions_target_agent_id", "actions", ["target_agent_id"], unique=False)
    op.create_index("ix_actions_target_host_id", "actions", ["target_host_id"], unique=False)
    op.create_index("ix_actions_action_type", "actions", ["action_type"], unique=False)
    op.create_index("ix_actions_approval_id", "actions", ["approval_id"], unique=False)
    op.create_index("ix_actions_expires_at", "actions", ["expires_at"], unique=False)
    op.create_index("ix_actions_status", "actions", ["status"], unique=False)
    op.create_index("ix_actions_agent_status", "actions", ["target_agent_id", "status"], unique=False)
    op.create_index("ix_actions_incident", "actions", ["incident_id", "requested_at"], unique=False)

    op.add_column("audit_records", sa.Column("previous_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_records", sa.Column("entry_hash", sa.String(length=64), nullable=True))
    op.create_index("ix_audit_records_entry_hash", "audit_records", ["entry_hash"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_records_entry_hash", table_name="audit_records")
    op.drop_column("audit_records", "entry_hash")
    op.drop_column("audit_records", "previous_hash")
    op.drop_table("actions")
    op.drop_table("approvals")
    op.drop_table("agent_nonces")
    op.drop_table("agents")
