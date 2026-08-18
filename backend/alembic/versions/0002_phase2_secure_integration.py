"""Phase 2 authenticated agents, approvals, actions, replay nonces, and audit hashes."""

from alembic import op
from sqlalchemy import Column, String, inspect

from app.database.models import Base

revision = "0002_phase2"
down_revision = "0001_phase1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    # This creates Phase 2 tables for databases already stamped at Phase 1.
    # It is intentionally idempotent because 0001 imports the current metadata
    # when a brand-new database is migrated from scratch.
    Base.metadata.create_all(bind=bind)
    inspector = inspect(bind)
    columns = {item["name"] for item in inspector.get_columns("audit_records")}
    if "previous_hash" not in columns:
        op.add_column("audit_records", Column("previous_hash", String(64), nullable=True))
    if "entry_hash" not in columns:
        op.add_column("audit_records", Column("entry_hash", String(64), nullable=True))
        op.create_index("ix_audit_records_entry_hash", "audit_records", ["entry_hash"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    for table in ("actions", "approvals", "agent_nonces", "agents"):
        if table in tables:
            op.drop_table(table)
    if "audit_records" in tables:
        columns = {item["name"] for item in inspect(bind).get_columns("audit_records")}
        indexes = {item["name"] for item in inspect(bind).get_indexes("audit_records")}
        if "ix_audit_records_entry_hash" in indexes:
            op.drop_index("ix_audit_records_entry_hash", table_name="audit_records")
        if "entry_hash" in columns:
            op.drop_column("audit_records", "entry_hash")
        if "previous_hash" in columns:
            op.drop_column("audit_records", "previous_hash")
