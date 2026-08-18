from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.database.session import get_db

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
        "remediation_enabled": False,
    }
