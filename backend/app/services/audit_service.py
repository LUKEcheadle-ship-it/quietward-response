from __future__ import annotations

import hashlib
import hmac
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
_CHECKPOINT_CONTEXT = b"quietward-response-audit-checkpoint-v1\x00"


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


def _checkpoint_unsigned_payload(
    *, generated_at: datetime, entries_checked: int, head_hash: str
) -> dict[str, Any]:
    timestamp = _as_utc(generated_at)
    return {
        "schema_version": "1.0",
        "generated_at": timestamp.isoformat(),
        "entries_checked": int(entries_checked),
        "head_hash": head_hash,
    }


def _checkpoint_bytes(
    *, generated_at: datetime, entries_checked: int, head_hash: str
) -> bytes:
    payload = _checkpoint_unsigned_payload(
        generated_at=generated_at,
        entries_checked=entries_checked,
        head_hash=head_hash,
    )
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _checkpoint_key(secret: str) -> bytes:
    return hashlib.sha256(_CHECKPOINT_CONTEXT + secret.encode("utf-8")).digest()


def create_audit_checkpoint(session: Session, *, secret: str) -> dict[str, Any]:
    """Return a signed audit-head checkpoint suitable for retention outside the DB.

    The signature key is configured separately from the database. Retaining a
    checkpoint elsewhere makes later full-chain recomputation or suffix deletion
    detectable as long as the checkpoint secret was not also compromised.
    """
    state = verify_audit_chain(session)
    if state["valid"] is not True:
        raise ValueError("cannot checkpoint an invalid audit chain")
    generated_at = datetime.now(timezone.utc)
    entries_checked = int(state["entries_checked"])
    head_hash = str(state["head_hash"])
    signature = hmac.new(
        _checkpoint_key(secret),
        _checkpoint_bytes(
            generated_at=generated_at,
            entries_checked=entries_checked,
            head_hash=head_hash,
        ),
        hashlib.sha256,
    ).hexdigest()
    return {
        **_checkpoint_unsigned_payload(
            generated_at=generated_at,
            entries_checked=entries_checked,
            head_hash=head_hash,
        ),
        "signature": signature,
    }


def verify_audit_checkpoint(
    session: Session,
    *,
    checkpoint: dict[str, Any],
    secret: str,
) -> dict[str, Any]:
    """Verify checkpoint authenticity and that its historical prefix still exists."""
    try:
        if checkpoint.get("schema_version") != "1.0":
            raise ValueError("checkpoint schema version is unsupported")
        generated_at_raw = checkpoint["generated_at"]
        generated_at = (
            generated_at_raw
            if isinstance(generated_at_raw, datetime)
            else datetime.fromisoformat(str(generated_at_raw).replace("Z", "+00:00"))
        )
        if generated_at.tzinfo is None or generated_at.utcoffset() is None:
            raise ValueError("checkpoint timestamp must include timezone")
        entries_checked = int(checkpoint["entries_checked"])
        if entries_checked < 0:
            raise ValueError("checkpoint entry count is invalid")
        head_hash = str(checkpoint["head_hash"])
        signature = str(checkpoint["signature"])
        if len(head_hash) != 64 or len(signature) != 64:
            raise ValueError("checkpoint hash/signature length is invalid")
        int(head_hash, 16)
        int(signature, 16)
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "valid": False,
            "signature_valid": False,
            "prefix_valid": False,
            "current_chain_valid": False,
            "error": "invalid_checkpoint_format",
        }

    expected_signature = hmac.new(
        _checkpoint_key(secret),
        _checkpoint_bytes(
            generated_at=generated_at,
            entries_checked=entries_checked,
            head_hash=head_hash,
        ),
        hashlib.sha256,
    ).hexdigest()
    signature_valid = hmac.compare_digest(expected_signature, signature)

    current = verify_audit_chain(session)
    current_chain_valid = current["valid"] is True
    records = _ordered_records(session) if current_chain_valid else []
    if entries_checked == 0:
        prefix_head = GENESIS_HASH
        prefix_present = True
    elif len(records) < entries_checked:
        prefix_head = ""
        prefix_present = False
    else:
        prefix_head = str(records[entries_checked - 1].entry_hash or "")
        prefix_present = True
    prefix_valid = prefix_present and hmac.compare_digest(prefix_head, head_hash)

    error: str | None = None
    if not signature_valid:
        error = "checkpoint_signature_invalid"
    elif not current_chain_valid:
        error = "current_audit_chain_invalid"
    elif not prefix_present:
        error = "checkpoint_prefix_missing_or_truncated"
    elif not prefix_valid:
        error = "checkpoint_prefix_hash_mismatch"

    return {
        "valid": signature_valid and current_chain_valid and prefix_valid,
        "signature_valid": signature_valid,
        "prefix_valid": prefix_valid,
        "current_chain_valid": current_chain_valid,
        "checkpoint_entries": entries_checked,
        "current_entries": int(current["entries_checked"]),
        "checkpoint_head_hash": head_hash,
        "current_head_hash": str(current["head_hash"]),
        "error": error,
    }
