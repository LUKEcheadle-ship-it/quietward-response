from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.audit_service import verify_audit_chain

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/verify")
def verify(db: Session = Depends(get_db)) -> dict[str, object]:
    return verify_audit_chain(db)
