from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.database.models import EventRecord, HostRecord
from app.database.session import get_db
from app.schemas.host import HostRead

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


def _host_dict(db: Session, host: HostRecord) -> dict[str, object]:
    event_count = db.scalar(
        select(func.count(EventRecord.event_id)).where(EventRecord.host_id == host.host_id)
    ) or 0
    incident_count = db.scalar(
        select(func.count(distinct(EventRecord.incident_id))).where(
            EventRecord.host_id == host.host_id,
            EventRecord.incident_id.is_not(None),
        )
    ) or 0
    return {
        "host_id": host.host_id,
        "hostname": host.hostname,
        "operating_system": host.operating_system,
        "agent": host.agent,
        "agent_version": host.agent_version,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
        "status": host.status,
        "event_count": event_count,
        "incident_count": incident_count,
    }


@router.get("", response_model=list[HostRead])
def list_hosts(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    hosts = list(db.scalars(select(HostRecord).order_by(HostRecord.last_seen.desc())))
    return [_host_dict(db, host) for host in hosts]


@router.get("/{host_id}", response_model=HostRead)
def get_host(host_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    host = db.get(HostRecord, host_id)
    if host is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="host not found")
    return _host_dict(db, host)
