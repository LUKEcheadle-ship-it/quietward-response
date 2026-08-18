from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.database.models import AuditRecord

logger = logging.getLogger("quietward_response.audit")


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
    record = AuditRecord(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        incident_id=incident_id,
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
            }
        },
    )
    return record
