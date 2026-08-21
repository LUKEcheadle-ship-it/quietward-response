from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN = "development-enrollment-token-change-me"
DEFAULT_DEVELOPMENT_AUDIT_CHECKPOINT_SECRET = "development-audit-checkpoint-secret-change-me"
_ANALYST_ROLES = {"viewer", "responder", "admin"}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_loopback_host(value: str) -> bool:
    host = value.strip().lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_analyst_credential(value: str) -> tuple[str, str, str]:
    """Validate `actor|role|sha256(token)` without ever storing plaintext tokens."""
    pieces = value.split("|")
    if len(pieces) != 3:
        raise ValueError(
            "QWR_ANALYST_CREDENTIALS entries must use actor_id|role|sha256_token_hash"
        )
    actor_id, role, token_hash = (item.strip() for item in pieces)
    role = role.lower()
    token_hash = token_hash.lower()
    if not actor_id or len(actor_id) > 128 or "|" in actor_id:
        raise ValueError("analyst actor_id must be 1-128 characters")
    if role not in _ANALYST_ROLES:
        raise ValueError("analyst role must be viewer, responder, or admin")
    if not _SHA256_RE.fullmatch(token_hash):
        raise ValueError("analyst token hash must be a lowercase/uppercase SHA-256 hex digest")
    return actor_id, role, token_hash


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

    api_max_request_bytes: int = Field(default=1_048_576, ge=4_096, le=8_388_608)
    api_rate_limit_per_minute: int = Field(default=600, ge=30, le=60_000)

    analyst_credentials: list[str] = Field(default_factory=list)

    enrollment_token: str = Field(
        default=DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN,
        min_length=24,
    )
    agent_replay_window_seconds: int = Field(default=300, ge=30, le=900)
    action_default_ttl_seconds: int = Field(default=600, ge=30, le=3600)
    require_agent_auth_for_quietward_events: bool = True

    # Independent from the database. Exported checkpoints can be retained outside
    # the DB and later verify that a historical prefix was not recomputed/truncated.
    audit_checkpoint_secret: str = Field(
        default=DEFAULT_DEVELOPMENT_AUDIT_CHECKPOINT_SECRET,
        min_length=32,
        max_length=512,
    )
    # Optional externally retained checkpoint to enforce at process startup. The
    # application never writes this path; operators can mount it read-only.
    trusted_audit_checkpoint_path: Path | None = None

    @property
    def development_actor_header_allowed(self) -> bool:
        return (
            self.environment.strip().lower() == "development"
            and _is_loopback_host(self.api_host)
        )

    @model_validator(mode="after")
    def enforce_security_boundary(self) -> "Settings":
        environment = self.environment.strip().lower()
        loopback = _is_loopback_host(self.api_host)

        parsed_credentials = [
            _validate_analyst_credential(value) for value in self.analyst_credentials
        ]
        hashes = [token_hash for _, _, token_hash in parsed_credentials]
        if len(hashes) != len(set(hashes)):
            raise ValueError("analyst credential token hashes must be unique")
        actors = [(actor_id, role) for actor_id, role, _ in parsed_credentials]
        if len(actors) != len(set(actors)):
            raise ValueError("analyst actor/role credential entries must be unique")
        if (environment != "development" or not loopback) and not parsed_credentials:
            raise ValueError(
                "QWR_ANALYST_CREDENTIALS is required outside loopback development"
            )

        if self.enrollment_token == DEFAULT_DEVELOPMENT_ENROLLMENT_TOKEN:
            if environment != "development" or not loopback:
                raise ValueError(
                    "QWR_ENROLLMENT_TOKEN must be replaced outside loopback development"
                )

        if self.audit_checkpoint_secret == DEFAULT_DEVELOPMENT_AUDIT_CHECKPOINT_SECRET:
            if environment != "development" or not loopback:
                raise ValueError(
                    "QWR_AUDIT_CHECKPOINT_SECRET must be replaced outside loopback development"
                )

        if self.trusted_audit_checkpoint_path is not None:
            checkpoint_path = self.trusted_audit_checkpoint_path.expanduser()
            if not checkpoint_path.is_absolute():
                raise ValueError("QWR_TRUSTED_AUDIT_CHECKPOINT_PATH must be absolute")
            self.trusted_audit_checkpoint_path = checkpoint_path

        if not self.require_agent_auth_for_quietward_events:
            if environment != "development" or not loopback:
                raise ValueError(
                    "QWR_REQUIRE_AGENT_AUTH_FOR_QUIETWARD_EVENTS may be disabled only "
                    "for loopback development"
                )

        if "*" in self.cors_origins and not loopback:
            raise ValueError("wildcard CORS is not allowed on a non-loopback API bind")

        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
