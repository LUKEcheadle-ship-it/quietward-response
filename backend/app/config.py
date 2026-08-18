from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "QuietWard Response"
    environment: str = "development"
    database_url: str = "sqlite:///./quietward_response.db"
    api_host: str = "0.0.0.0"
    api_port: int = 8001
    frontend_origin: str = "http://localhost:3000"
    correlation_window_seconds: int = 300
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
