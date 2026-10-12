from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN = "development-enrollment-token-change-me"


def _is_loopback_host(value: str) -> bool:
    host = value.strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_ENV_FILE),
        env_prefix="QWR_",
        extra="ignore",
    )

    environment: str = "development"
    database_url: str = "sqlite:///./quietward-response.db"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8002, ge=1, le=65535)
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ]
    )
    correlation_window_seconds: int = Field(default=300, ge=30, le=3600)
    log_level: str = "INFO"

    # Local development has a known loopback-only fallback so a fresh clone can
    # start without secret provisioning. Any non-loopback or non-development
    # runtime must set its own sufficiently long token.
    enrollment_token: str = Field(
        default=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
        min_length=24,
    )
    agent_replay_window_seconds: int = Field(default=300, ge=30, le=900)
    action_default_ttl_seconds: int = Field(default=600, ge=30, le=3600)
    require_agent_auth_for_quietward_events: bool = True
    # Named analysts mapped to SHA-256 token digests; never store raw tokens here.
    analyst_token_hashes: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def enforce_security_boundary(self) -> "Settings":
        environment = self.environment.strip().lower()
        loopback = _is_loopback_host(self.api_host)

        if self.enrollment_token == DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN:
            if environment != "development" or not loopback:
                raise ValueError(
                    "QWR_ENROLLMENT_TOKEN must be replaced outside loopback development"
                )

        # Disabling authenticated QuietWard telemetry is a loopback-only development
        # escape hatch. Never permit that setting on a remotely reachable bind.
        if not self.require_agent_auth_for_quietward_events:
            if environment != "development" or not loopback:
                raise ValueError(
                    "QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS may be disabled only "
                    "for loopback development"
                )

        if "*" in self.cors_origins and not loopback:
            raise ValueError("wildcard CORS is not allowed on a non-loopback API bind")

        for name, digest in self.analyst_token_hashes.items():
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("QWR_ANALYST_TOKEN_HASHES requires simple analyst names and lowercase SHA-256 digests")
        if len(set(self.analyst_token_hashes.values())) != len(self.analyst_token_hashes):
            raise ValueError("Each analyst must have a distinct token digest")
        if (environment != "development" or not loopback) and not self.analyst_token_hashes:
            raise ValueError("QWR_ANALYST_TOKEN_HASHES must be configured outside loopback development")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
