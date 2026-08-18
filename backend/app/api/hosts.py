from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.host import Host
from app.schemas.host import HostResponse

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostResponse])
def list_hosts(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    return db.scalars(select(Host).order_by(Host.last_seen.desc()).limit(limit)).all()


@router.get("/{host_id}", response_model=HostResponse)
def get_host(host_id: str, db: Session = Depends(get_db)):
    host = db.get(Host, host_id)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")
    return host
