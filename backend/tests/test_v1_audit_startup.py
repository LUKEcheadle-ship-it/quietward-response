from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.database.models import AuditRecord
from app.database.session import Database
from app.main import create_app


def test_startup_refuses_a_preexisting_broken_audit_chain(tmp_path: Path) -> None:
    database_path = tmp_path / "broken-audit.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    database = Database(database_url)
    try:
        database.create_all()
        with database.session_factory() as session:
            session.add(
                AuditRecord(
                    actor_type="test",
                    actor_id="test",
                    action="tampered_entry",
                    resource_type="test",
                    resource_id="broken",
                    details={"synthetic": True},
                    previous_hash="0" * 64,
                    entry_hash="f" * 64,
                )
            )
            session.commit()
    finally:
        database.dispose()

    with pytest.raises(RuntimeError, match="audit chain verification failed at startup"):
        with TestClient(create_app(database_url=database_url)):
            pass
