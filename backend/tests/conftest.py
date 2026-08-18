from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path: Path):
    database = tmp_path / "test.db"
    # Pin every security-sensitive setting that the tests rely on so a developer's
    # repository-root .env cannot silently change the test contract.
    settings = Settings(
        database_url=f"sqlite:///{database.as_posix()}",
        cors_origins=["http://localhost:3001"],
        correlation_window_seconds=300,
        log_level="WARNING",
        enrollment_token="development-enrollment-token-change-me",
        agent_replay_window_seconds=300,
        action_default_ttl_seconds=600,
        require_agent_auth_for_quietward_events=True,
    )
    with TestClient(create_app(settings=settings)) as test_client:
        yield test_client


@pytest.fixture
def event_factory():
    base = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)

    def build(
        index: int = 0,
        *,
        host_id: str = "host-alpha",
        event_type: str = "process_observed",
        category: str = "execution",
        severity: str = "medium",
        confidence: float = 0.7,
        summary: str = "Synthetic process observation",
        **extra: Any,
    ) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": "1.0",
            "event_id": str(uuid5(NAMESPACE_URL, f"qwr-test:{host_id}:{index}:{event_type}")),
            "source": "test-sensor",
            "source_version": "1.2.3",
            "host_id": host_id,
            "host_name": f"{host_id}.example.test",
            "timestamp": (base + timedelta(seconds=index)).isoformat(),
            "event_type": event_type,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "evidence": {"synthetic": True, "sequence": index},
            "metadata": {"operating_system": "Test OS"},
        }
        value.update(extra)
        return value

    return build
