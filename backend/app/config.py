from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_ENV_FILE),
        env_prefix="QWR_",
        extra="ignore",
    )

    environment: str = "development"
    database_url: str = "sqlite:///./quietward-response.db"
    api_host: str = "127.0.0.1"
    api_port: int = 8002
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3001"])
    correlation_window_seconds: int = Field(default=300, ge=30, le=3600)
    log_level: str = "INFO"

    # Phase 2/v1 local enrollment is intentionally explicit. Replace this value in .env.
    enrollment_token: str = "development-enrollment-token-change-me"
    agent_replay_window_seconds: int = Field(default=300, ge=30, le=900)
    action_default_ttl_seconds: int = Field(default=600, ge=30, le=3600)
    require_agent_auth_for_quietward_events: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
