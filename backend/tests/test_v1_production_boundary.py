from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import Settings
from app.database.models import AuditRecord
from app.main import create_app


def test_unauthenticated_synthetic_sensor_is_development_only_and_audited(tmp_path: Path, event_factory) -> None:
    settings = Settings(
        environment="production",
        database_url=f"sqlite:///{(tmp_path / 'production.db').as_posix()}",
        enrollment_token="production-enrollment-token-for-test",
        analyst_credentials=[
            "production-admin|admin|"
            + hashlib.sha256(b"production-admin-token").hexdigest()
        ],
        audit_checkpoint_secret="production-audit-checkpoint-secret-boundary-0123456789",
        cors_origins=["http://localhost:3001"],
        log_level="WARNING",
    )
    with TestClient(create_app(settings=settings)) as client:
        response = client.post("/api/v1/events", json=event_factory())
        assert response.status_code == 401
        assert response.json()["detail"]["code"] == "unauthenticated_sensor_source"

        with client.app.state.database.session_factory() as session:
            audit = session.scalars(select(AuditRecord)).first()
            assert audit is not None
            assert audit.action == "event_rejected"
            assert audit.details["reason"] == "unauthenticated_sensor_source"
