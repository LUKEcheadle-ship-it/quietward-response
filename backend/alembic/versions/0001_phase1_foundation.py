"""Phase 1 foundation tables.

Revision ID: 0001_phase1
Revises: None
"""
from typing import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0001_phase1"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("host_id", sa.String(255), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("operating_system", sa.String(100)),
        sa.Column("agent", sa.String(100), nullable=False),
        sa.Column("agent_version", sa.String(50)),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
    )
    op.create_index("ix_hosts_hostname", "hosts", ["hostname"])
    op.create_index("ix_hosts_last_seen", "hosts", ["last_seen"])
    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
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
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_updated_at", "incidents", ["updated_at"])
    op.create_index("ix_incidents_last_event_at", "incidents", ["last_event_at"])
    op.create_table(
        "events",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("schema_version", sa.String(10), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("source_version", sa.String(50)),
        sa.Column("host_id", sa.String(255), sa.ForeignKey("hosts.host_id"), nullable=False),
        sa.Column("host_name", sa.String(255)),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("category", sa.String(100)),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("process", sa.JSON(), nullable=False),
        sa.Column("file", sa.JSON(), nullable=False),
        sa.Column("network", sa.JSON(), nullable=False),
        sa.Column("persistence", sa.JSON(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("incident_id", sa.String(36), sa.ForeignKey("incidents.incident_id")),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    for column in ("source", "host_id", "timestamp", "event_type", "category", "severity", "incident_id"):
        op.create_index(f"ix_events_{column}", "events", [column])
    op.create_table(
        "audits",
        sa.Column("audit_id", sa.String(36), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_type", sa.String(50), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    for column in ("timestamp", "action", "resource_type", "resource_id"):
        op.create_index(f"ix_audits_{column}", "audits", [column])


def downgrade() -> None:
    op.drop_table("audits")
    op.drop_table("events")
    op.drop_table("incidents")
    op.drop_table("hosts")
