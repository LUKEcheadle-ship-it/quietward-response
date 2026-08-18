from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import AuditRecord

logger = logging.getLogger("quietward_response.audit")
GENESIS_HASH = "0" * 64


def _canonical_payload(
    *,
    audit_id: str,
    timestamp: datetime,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any],
    incident_id: str | None,
    previous_hash: str,
) -> bytes:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    value = {
        "audit_id": audit_id,
        "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
        "incident_id": incident_id,
        "previous_hash": previous_hash,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash_entry(**kwargs: Any) -> str:
    return hashlib.sha256(_canonical_payload(**kwargs)).hexdigest()


def _ordered_records(session: Session) -> list[AuditRecord]:
    return list(
        session.scalars(
            select(AuditRecord).order_by(AuditRecord.timestamp.asc(), AuditRecord.audit_id.asc())
        )
    )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def backfill_legacy_audit_chain(session: Session) -> int:
    """Hash Phase 1 rows once when every existing row is still unhashed.

    A partially hashed database is intentionally not rewritten; verification will
    report it as broken instead of hiding a potentially suspicious condition.
    """
    records = _ordered_records(session)
    if not records or any(record.entry_hash for record in records):
        return 0
    previous_hash = GENESIS_HASH
    for record in records:
        record.previous_hash = previous_hash
        record.entry_hash = _hash_entry(
            audit_id=record.audit_id,
            timestamp=record.timestamp,
            actor_type=record.actor_type,
            actor_id=record.actor_id,
            action=record.action,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            details=record.details or {},
            incident_id=record.incident_id,
            previous_hash=previous_hash,
        )
        previous_hash = record.entry_hash
    session.flush()
    return len(records)


def record_audit(
    session: Session,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
    incident_id: str | None = None,
) -> AuditRecord:
    previous = session.scalars(
        select(AuditRecord)
        .order_by(AuditRecord.timestamp.desc(), AuditRecord.audit_id.desc())
        .limit(1)
    ).first()
    previous_hash = previous.entry_hash if previous and previous.entry_hash else GENESIS_HASH
    timestamp = datetime.now(timezone.utc)
    # The chain is verified in timestamp/audit_id order. Keep generated timestamps
    # strictly monotonic so equal-resolution clocks or a small wall-clock rollback
    # cannot reorder newly appended entries and falsely break the chain.
    if previous is not None and timestamp <= _as_utc(previous.timestamp):
        timestamp = _as_utc(previous.timestamp) + timedelta(microseconds=1)
    audit_id = str(uuid4())
    resolved_details = details or {}
    entry_hash = _hash_entry(
        audit_id=audit_id,
        timestamp=timestamp,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=resolved_details,
        incident_id=incident_id,
        previous_hash=previous_hash,
    )
    record = AuditRecord(
        audit_id=audit_id,
        timestamp=timestamp,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=resolved_details,
        incident_id=incident_id,
        previous_hash=previous_hash,
        entry_hash=entry_hash,
    )
    session.add(record)
    session.flush()
    logger.info(
        "audit operation recorded",
        extra={
            "audit": {
                "audit_id": record.audit_id,
                "actor_type": actor_type,
                "actor_id": actor_id,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "incident_id": incident_id,
                "entry_hash": entry_hash,
            }
        },
    )
    return record


def verify_audit_chain(session: Session) -> dict[str, Any]:
    records = _ordered_records(session)
    expected_previous = GENESIS_HASH
    errors: list[dict[str, str]] = []
    for record in records:
        previous_hash = record.previous_hash or GENESIS_HASH
        if previous_hash != expected_previous:
            errors.append({"audit_id": record.audit_id, "error": "previous_hash_mismatch"})
        expected_entry = _hash_entry(
            audit_id=record.audit_id,
            timestamp=record.timestamp,
            actor_type=record.actor_type,
            actor_id=record.actor_id,
            action=record.action,
            resource_type=record.resource_type,
            resource_id=record.resource_id,
            details=record.details or {},
            incident_id=record.incident_id,
            previous_hash=previous_hash,
        )
        if record.entry_hash != expected_entry:
            errors.append({"audit_id": record.audit_id, "error": "entry_hash_mismatch"})
        expected_previous = record.entry_hash or ""
    return {
        "valid": not errors,
        "entries_checked": len(records),
        "head_hash": expected_previous if records else GENESIS_HASH,
        "errors": errors,
    }
