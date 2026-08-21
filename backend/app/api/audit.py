from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.audit import AuditCheckpoint, AuditCheckpointVerification
from app.services.audit_service import (
    create_audit_checkpoint,
    verify_audit_chain,
    verify_audit_checkpoint,
)

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get("/verify")
def verify(db: Session = Depends(get_db)) -> dict[str, object]:
    return verify_audit_chain(db)


@router.get("/checkpoint", response_model=AuditCheckpoint)
def checkpoint(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return create_audit_checkpoint(
        db,
        secret=request.app.state.settings.audit_checkpoint_secret,
    )


@router.post("/checkpoint/verify", response_model=AuditCheckpointVerification)
def verify_checkpoint(
    payload: AuditCheckpoint,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return verify_audit_checkpoint(
        db,
        checkpoint=payload.model_dump(mode="python"),
        secret=request.app.state.settings.audit_checkpoint_secret,
    )
