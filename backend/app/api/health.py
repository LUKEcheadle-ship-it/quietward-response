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
    mutating = {
        action_type
        for action_type, definition in ACTION_REGISTRY.items()
        if definition.risk_level in {"medium", "high", "critical"}
        or action_type == "restart_quietward_demo_service"
    }
    diagnostics = {
        action_type
        for action_type in ACTION_REGISTRY
        if action_type.startswith("collect_")
    }
    return {
        "status": "ok",
        "service": "quietward-response",
        "version": __version__,
        "database": "ok",
        # Generic/arbitrary remediation remains disabled; only registered typed
        # actions can execute through approval + deterministic policy + agent allowlist.
        "remediation_enabled": False,
        "controlled_response_enabled": bool(ACTION_REGISTRY),
        "controlled_action_count": len(ACTION_REGISTRY),
        "read_only_diagnostic_count": len(diagnostics),
        "state_changing_action_count": len(mutating),
        "response_scope": "typed_controlled_response_v12",
        "generic_command_execution": False,
        "single_worker_required": True,
    }
