"""Frozen Phase 1 event, host, incident, and audit schema.

This migration is intentionally explicit. Do not import current ORM metadata here:
old migrations must keep creating the schema that existed at that revision even
as later model versions evolve.
"""

from alembic import op
import sqlalchemy as sa

revision = "0001_phase1"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("host_id", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("operating_system", sa.String(length=128), nullable=True),
        sa.Column("agent", sa.String(length=128), nullable=False),
        sa.Column("agent_version", sa.String(length=64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
    )
    op.create_index("ix_hosts_hostname", "hosts", ["hostname"], unique=False)
    op.create_index("ix_hosts_last_seen", "hosts", ["last_seen"], unique=False)

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("affected_hosts", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False),
        sa.Column("probable_cause", sa.Text(), nullable=False),
        sa.Column("correlation_reasons", sa.JSON(), nullable=False),
        sa.Column("recommended_actions", sa.JSON(), nullable=False),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"], unique=False)
    op.create_index("ix_incidents_severity", "incidents", ["severity"], unique=False)
    op.create_index("ix_incidents_last_event_at", "incidents", ["last_event_at"], unique=False)

    op.create_table(
        "events",
        sa.Column("event_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("source_version", sa.String(length=64), nullable=True),
        sa.Column("host_id", sa.String(length=128), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("host_name", sa.String(length=255), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("normalized", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.incident_id"), nullable=True),
    )
    op.create_index("ix_events_source", "events", ["source"], unique=False)
    op.create_index("ix_events_host_id", "events", ["host_id"], unique=False)
    op.create_index("ix_events_occurred_at", "events", ["occurred_at"], unique=False)
    op.create_index("ix_events_event_type", "events", ["event_type"], unique=False)
    op.create_index("ix_events_category", "events", ["category"], unique=False)
    op.create_index("ix_events_severity", "events", ["severity"], unique=False)
    op.create_index("ix_events_incident_id", "events", ["incident_id"], unique=False)
    op.create_index("ix_events_host_time", "events", ["host_id", "occurred_at"], unique=False)
    op.create_index("ix_events_type_time", "events", ["event_type", "occurred_at"], unique=False)

    op.create_table(
        "audit_records",
        sa.Column("audit_id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_type", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("incident_id", sa.String(length=36), sa.ForeignKey("incidents.incident_id"), nullable=True),
    )
    op.create_index("ix_audit_records_action", "audit_records", ["action"], unique=False)
    op.create_index("ix_audit_records_resource_type", "audit_records", ["resource_type"], unique=False)
    op.create_index("ix_audit_records_resource_id", "audit_records", ["resource_id"], unique=False)
    op.create_index("ix_audit_records_incident_id", "audit_records", ["incident_id"], unique=False)
    op.create_index("ix_audit_resource", "audit_records", ["resource_type", "resource_id"], unique=False)


def downgrade() -> None:
    op.drop_table("audit_records")
    op.drop_table("events")
    op.drop_table("incidents")
    op.drop_table("hosts")
