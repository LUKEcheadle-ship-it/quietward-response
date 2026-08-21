from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN, Settings
from app.database.session import Database


_TEST_ANALYST_CREDENTIALS = [
    "config-admin|admin|" + hashlib.sha256(b"config-admin-token").hexdigest()
]
_TEST_AUDIT_SECRET = "test-audit-checkpoint-secret-config-boundary-0123456789"


def _remote_prerequisites() -> dict[str, object]:
    return {
        "analyst_credentials": _TEST_ANALYST_CREDENTIALS,
        "audit_checkpoint_secret": _TEST_AUDIT_SECRET,
    }


def test_development_fallback_token_is_loopback_only() -> None:
    development = Settings(
        environment="development",
        api_host="127.0.0.1",
        enrollment_token=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
    )
    assert development.enrollment_token == DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN

    with pytest.raises(ValidationError, match="QWR_ENROLLMENT_TOKEN"):
        Settings(
            environment="production",
            enrollment_token=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
            **_remote_prerequisites(),
        )

    with pytest.raises(ValidationError, match="QWR_ENROLLMENT_TOKEN"):
        Settings(
            environment="development",
            api_host="0.0.0.0",
            enrollment_token=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
            **_remote_prerequisites(),
        )


def test_enrollment_token_has_minimum_length() -> None:
    with pytest.raises(ValidationError):
        Settings(environment="development", enrollment_token="too-short")


def test_quietward_auth_can_be_disabled_only_on_loopback_development() -> None:
    allowed = Settings(
        environment="development",
        api_host="localhost",
        require_agent_auth_for_quietward_events=False,
    )
    assert allowed.require_agent_auth_for_quietward_events is False

    with pytest.raises(
        ValidationError,
        match="QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS",
    ):
        Settings(
            environment="production",
            enrollment_token="production-enrollment-token-for-test",
            require_agent_auth_for_quietward_events=False,
            **_remote_prerequisites(),
        )

    with pytest.raises(
        ValidationError,
        match="QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS",
    ):
        Settings(
            environment="development",
            api_host="0.0.0.0",
            enrollment_token="remote-development-enrollment-token",
            require_agent_auth_for_quietward_events=False,
            **_remote_prerequisites(),
        )


def test_non_loopback_bind_rejects_wildcard_cors() -> None:
    with pytest.raises(ValidationError, match="wildcard CORS"):
        Settings(
            environment="development",
            api_host="0.0.0.0",
            enrollment_token="remote-development-enrollment-token",
            cors_origins=["*"],
            **_remote_prerequisites(),
        )


def test_api_port_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Settings(api_port=0)
    with pytest.raises(ValidationError):
        Settings(api_port=65536)


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
