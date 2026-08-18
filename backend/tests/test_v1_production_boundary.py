from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_unauthenticated_synthetic_sensor_is_development_only(tmp_path: Path, event_factory) -> None:
    settings = Settings(
        environment="production",
        database_url=f"sqlite:///{(tmp_path / 'production.db').as_posix()}",
        enrollment_token="production-enrollment-token-for-test",
        cors_origins=["http://localhost:3001"],
        log_level="WARNING",
    )
    with TestClient(create_app(settings=settings)) as client:
        response = client.post("/api/v1/events", json=event_factory())

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "unauthenticated_sensor_source"
