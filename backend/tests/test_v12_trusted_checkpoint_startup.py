from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.database.session import Database
from app.main import create_app
from app.services.audit_service import create_audit_checkpoint, record_audit


SECRET = "trusted-checkpoint-test-secret-0123456789abcdef"


def _seed_database(path: Path) -> dict:
    database = Database(f"sqlite:///{path.as_posix()}")
    try:
        database.create_all()
        with database.session_factory() as session:
            record_audit(
                session,
                actor_type="system",
                actor_id="checkpoint-test",
                action="seed",
                resource_type="test",
                resource_id="seed-1",
                details={"sequence": 1},
            )
            session.commit()
            return create_audit_checkpoint(session, secret=SECRET)
    finally:
        database.dispose()


def _append_database(path: Path) -> None:
    database = Database(f"sqlite:///{path.as_posix()}")
    try:
        with database.session_factory() as session:
            record_audit(
                session,
                actor_type="system",
                actor_id="checkpoint-test",
                action="append",
                resource_type="test",
                resource_id="seed-2",
                details={"sequence": 2},
            )
            session.commit()
    finally:
        database.dispose()


def _settings(database: Path, checkpoint: Path) -> Settings:
    return Settings(
        environment="development",
        api_host="127.0.0.1",
        database_url=f"sqlite:///{database.as_posix()}",
        log_level="WARNING",
        audit_checkpoint_secret=SECRET,
        trusted_audit_checkpoint_path=checkpoint.resolve(),
    )


def test_valid_retained_checkpoint_allows_startup(tmp_path: Path) -> None:
    database = tmp_path / "response.db"
    checkpoint_path = tmp_path / "trusted-checkpoint.json"
    checkpoint_path.write_text(
        json.dumps(_seed_database(database), sort_keys=True),
        encoding="utf-8",
    )

    with TestClient(create_app(settings=_settings(database, checkpoint_path))) as client:
        assert client.get("/health").status_code == 200


def test_retained_checkpoint_allows_legitimate_later_audit_appends(tmp_path: Path) -> None:
    database = tmp_path / "response-append.db"
    checkpoint_path = tmp_path / "trusted-checkpoint-append.json"
    checkpoint_path.write_text(
        json.dumps(_seed_database(database), sort_keys=True),
        encoding="utf-8",
    )
    _append_database(database)

    with TestClient(create_app(settings=_settings(database, checkpoint_path))) as client:
        assert client.get("/health").status_code == 200


def test_tampered_retained_checkpoint_blocks_startup(tmp_path: Path) -> None:
    database = tmp_path / "response-tamper.db"
    checkpoint_path = tmp_path / "trusted-checkpoint-tamper.json"
    checkpoint = _seed_database(database)
    checkpoint["signature"] = "0" * 64
    checkpoint_path.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")

    with pytest.raises(RuntimeError, match="trusted audit checkpoint verification failed"):
        with TestClient(create_app(settings=_settings(database, checkpoint_path))):
            pass


def test_missing_retained_checkpoint_blocks_startup(tmp_path: Path) -> None:
    database = tmp_path / "response-missing.db"
    _seed_database(database)
    missing = (tmp_path / "does-not-exist.json").resolve()

    with pytest.raises(RuntimeError, match="trusted audit checkpoint is missing"):
        with TestClient(create_app(settings=_settings(database, missing))):
            pass


def test_relative_trusted_checkpoint_path_is_rejected() -> None:
    with pytest.raises(ValidationError, match="QWR_TRUSTED_AUDIT_CHECKPOINT_PATH"):
        Settings(
            environment="development",
            api_host="127.0.0.1",
            trusted_audit_checkpoint_path=Path("relative-checkpoint.json"),
        )
