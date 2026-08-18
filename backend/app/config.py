from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
