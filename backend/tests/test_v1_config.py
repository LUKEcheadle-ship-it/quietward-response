from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN, Settings


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
