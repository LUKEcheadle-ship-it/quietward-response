import os
import sys
from pathlib import Path
from uuid import uuid4

os.environ["DATABASE_URL"] = "sqlite:///./test_quietward_response.db"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from app.database.models import Base
from app.database.session import engine
from app.main import app


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def event_factory():
    def make(**overrides):
        event = {
            "schema_version": "1.0",
            "event_id": str(uuid4()),
            "source": "quietward",
            "source_version": "0.9.0",
            "host_id": "host-alpha",
            "host_name": "alpha-workstation",
            "timestamp": "2026-08-17T21:41:03Z",
            "event_type": "file.created",
            "category": "persistence",
            "severity": "high",
            "confidence": 82,
            "summary": "Unknown executable created",
            "file": {"path": "C:/ProgramData/cache/update-helper.exe", "sha256": "demo-hash"},
            "process": {"pid": 4120, "executable": "C:/ProgramData/cache/update-helper.exe"},
            "evidence": {"synthetic": True},
            "metadata": {"operating_system": "Windows 11"},
        }
        event.update(overrides)
        return event
    return make
