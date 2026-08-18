import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.audit import Audit

logger = logging.getLogger("quietward.audit")


def record_audit(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
    actor_type: str = "system",
    actor_id: str = "quietward-response",
) -> Audit:
    entry = Audit(
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
    )
    db.add(entry)
    logger.info(json.dumps({"audit": action, "resource_type": resource_type, "resource_id": resource_id, "details": details or {}}, default=str))
    return entry
