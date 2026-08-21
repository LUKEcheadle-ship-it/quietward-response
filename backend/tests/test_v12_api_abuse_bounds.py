from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _client(tmp_path: Path, *, max_bytes: int = 4096, rate: int = 30):
    database = tmp_path / "abuse-bounds.db"
    settings = Settings(
        environment="development",
        database_url=f"sqlite:///{database.as_posix()}",
        cors_origins=["http://localhost:3001"],
        correlation_window_seconds=300,
        log_level="WARNING",
        enrollment_token="development-enrollment-token-change-me",
        agent_replay_window_seconds=300,
        action_default_ttl_seconds=600,
        require_agent_auth_for_quietward_events=True,
        api_max_request_bytes=max_bytes,
        api_rate_limit_per_minute=rate,
    )
    return TestClient(create_app(settings=settings))


def test_oversized_request_is_rejected_before_schema_processing(tmp_path: Path) -> None:
    with _client(tmp_path, max_bytes=4096) as client:
        response = client.post(
            "/api/v1/events",
            content=b"x" * 5000,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["detail"]["code"] == "request_too_large"
        assert response.headers["cache-control"].startswith("no-store")
        assert response.headers["x-content-type-options"] == "nosniff"


def test_api_rate_limit_is_bounded_per_client(tmp_path: Path) -> None:
    with _client(tmp_path, rate=30) as client:
        for _ in range(30):
            response = client.get("/api/v1/overview")
            assert response.status_code == 200
        blocked = client.get("/api/v1/overview")
        assert blocked.status_code == 429
        assert blocked.json()["detail"]["code"] == "api_rate_limit_exceeded"
        assert blocked.headers["retry-after"] == "60"
        assert blocked.headers["cache-control"].startswith("no-store")


def test_non_api_health_check_is_not_consumed_by_api_rate_bucket(tmp_path: Path) -> None:
    with _client(tmp_path, rate=30) as client:
        for _ in range(40):
            response = client.get("/health")
            assert response.status_code == 200
        assert client.get("/api/v1/overview").status_code == 200
