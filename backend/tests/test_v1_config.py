from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN, Settings
from app.database.session import Database


def test_development_fallback_token_is_allowed_only_for_development() -> None:
    development = Settings(
        environment="development",
        enrollment_token=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
    )
    assert development.enrollment_token == DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN

    with pytest.raises(ValidationError, match="QWR_ENROLLMENT_TOKEN"):
        Settings(
            environment="production",
            enrollment_token=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
        )


def test_enrollment_token_has_minimum_length() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="development", enrollment_token="too-short")


def test_quietward_auth_cannot_be_disabled_outside_development() -> None:
    with pytest.raises(
        ValidationError,
        match="QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS",
    ):
        Settings(
            environment="production",
            enrollment_token="production-enrollment-token-for-test",
            require_agent_auth_for_quietward_events=False,
        )


def test_local_sqlite_database_is_private_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode semantics do not apply on Windows")
    database_path = tmp_path / "private-response.db"
    database = Database(f"sqlite:///{database_path.as_posix()}")
    try:
        database.create_all()
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
    finally:
        database.dispose()
