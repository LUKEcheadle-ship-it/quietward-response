from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.database.session import get_db
from app.services.action_registry import ACTION_REGISTRY

router = APIRouter(tags=["health"])


@router.get("/health")
@router.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict[str, object]:
    db.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "service": "quietward-response",
        "version": __version__,
        "database": "ok",
        # Backward-compatible Phase 1 flag: general host remediation is still off.
        "remediation_enabled": False,
        "controlled_response_enabled": bool(ACTION_REGISTRY),
        "controlled_action_count": len(ACTION_REGISTRY),
        "response_scope": "read_only_diagnostics_plus_demo_fixture",
        "single_worker_required": True,
    }
