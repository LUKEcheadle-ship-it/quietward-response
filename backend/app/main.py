from __future__ import annotations

import json
import os
import stat
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api import actions, agents, audit, events, health, hosts, incidents, overview
from app.config import Settings, get_settings
from app.database.session import Database
from app.logging import configure_logging
from app.request_serialization import SerializedRequestMiddleware
from app.services.analyst_auth import AnalystAuthMiddleware
from app.services.audit_service import (
    backfill_legacy_audit_chain,
    record_audit,
    verify_audit_chain,
    verify_audit_checkpoint,
)

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_MAX_TRUSTED_CHECKPOINT_BYTES = 16_384


def _link_like(details: os.stat_result) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(
        attributes & _FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    if left.st_ino and right.st_ino:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return (
        left.st_dev,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _load_trusted_audit_checkpoint(path) -> dict[str, object]:
    checkpoint_path = path.expanduser()
    try:
        before = checkpoint_path.lstat()
    except OSError as exc:
        raise RuntimeError(
            "trusted audit checkpoint is missing, unreadable, or invalid JSON; refusing startup"
        ) from exc
    if _link_like(before):
        raise RuntimeError(
            "trusted audit checkpoint must not be a symbolic link or reparse point; refusing startup"
        )
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(
            "trusted audit checkpoint must be a regular file; refusing startup"
        )
    if before.st_size > _MAX_TRUSTED_CHECKPOINT_BYTES:
        raise RuntimeError(
            "trusted audit checkpoint file is unexpectedly large; refusing startup"
        )
    if os.name != "nt" and stat.S_IMODE(before.st_mode) & 0o022:
        raise RuntimeError(
            "trusted audit checkpoint must not be group/world writable; refusing startup"
        )

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(checkpoint_path, flags)
    except OSError as exc:
        raise RuntimeError(
            "trusted audit checkpoint is missing, unreadable, or invalid JSON; refusing startup"
        ) from exc
    chunks: list[bytes] = []
    total = 0
    try:
        opened = os.fstat(descriptor)
        if _link_like(opened) or not stat.S_ISREG(opened.st_mode) or not _same_file(before, opened):
            raise RuntimeError(
                "trusted audit checkpoint changed during validation; refusing startup"
            )
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_TRUSTED_CHECKPOINT_BYTES:
                raise RuntimeError(
                    "trusted audit checkpoint file is unexpectedly large; refusing startup"
                )
            chunks.append(chunk)
    finally:
        os.close(descriptor)

    try:
        after = checkpoint_path.lstat()
    except OSError as exc:
        raise RuntimeError(
            "trusted audit checkpoint changed during read; refusing startup"
        ) from exc
    if _link_like(after) or not _same_file(before, after):
        raise RuntimeError(
            "trusted audit checkpoint changed during read; refusing startup"
        )

    try:
        raw = b"".join(chunks).decode("utf-8")
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "trusted audit checkpoint is missing, unreadable, or invalid JSON; refusing startup"
        ) from exc
    if not isinstance(value, dict):
        raise RuntimeError("trusted audit checkpoint must be a JSON object; refusing startup")
    return value


def create_app(
    *,
    database_url: str | None = None,
    settings: Settings | None = None,
    create_schema: bool = True,
) -> FastAPI:
    """Build the API application.

    Tests and explicitly embedded development callers may request direct SQLAlchemy
    schema creation. Normal launchers call `runtime_app()` and rely on the documented
    Alembic migration step, preventing application startup from silently masking
    migration drift.
    """
    resolved = settings or get_settings()
    if database_url:
        resolved = resolved.model_copy(update={"database_url": database_url})
    configure_logging(resolved.log_level)
    database = Database(resolved.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            if create_schema:
                database.create_all()
            else:
                database.harden_local_file_permissions()
            with database.session_factory() as session:
                if backfill_legacy_audit_chain(session):
                    session.commit()
                audit_state = verify_audit_chain(session)
                if audit_state["valid"] is not True:
                    raise RuntimeError(
                        "audit chain verification failed at startup; refusing to serve requests"
                    )
                if resolved.trusted_audit_checkpoint_path is not None:
                    checkpoint = _load_trusted_audit_checkpoint(
                        resolved.trusted_audit_checkpoint_path
                    )
                    checkpoint_state = verify_audit_checkpoint(
                        session,
                        checkpoint=checkpoint,
                        secret=resolved.audit_checkpoint_secret,
                    )
                    if checkpoint_state["valid"] is not True:
                        raise RuntimeError(
                            "trusted audit checkpoint verification failed at startup "
                            f"({checkpoint_state.get('error')}); refusing to serve requests"
                        )
            yield
        finally:
            database.dispose()

    application = FastAPI(
        title="QuietWard Response API",
        version=__version__,
        description=(
            "Deterministic event ingestion, incident correlation, investigation, "
            "authenticated agents, analyst RBAC, policy-controlled response actions, "
            "and tamper-evident audit."
        ),
        lifespan=lifespan,
    )
    application.state.database = database
    application.state.settings = resolved

    application.add_middleware(AnalystAuthMiddleware)
    application.add_middleware(
        SerializedRequestMiddleware,
        max_request_bytes=resolved.api_max_request_bytes,
        rate_limit_per_minute=resolved.api_rate_limit_per_minute,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Actor-ID",
            "X-QWR-Enrollment-Token",
            "X-QWR-Agent-ID",
            "X-QWR-Key-ID",
            "X-QWR-Timestamp",
            "X-QWR-Nonce",
            "X-QWR-Signature",
        ],
    )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        if request.method == "POST" and request.url.path == "/api/v1/events":
            with database.session_factory() as session:
                record_audit(
                    session,
                    actor_type="unknown_sensor",
                    actor_id="unvalidated",
                    action="event_rejected",
                    resource_type="event",
                    resource_id="unvalidated",
                    details={
                        "reason": "schema_validation_failed",
                        "errors": [
                            {
                                "location": [str(part) for part in error["loc"]],
                                "message": error["msg"],
                                "type": error["type"],
                            }
                            for error in exc.errors()
                        ],
                    },
                )
                session.commit()
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder({"detail": exc.errors()}),
        )

    application.include_router(health.router)
    application.include_router(events.router)
    application.include_router(incidents.router)
    application.include_router(hosts.router)
    application.include_router(overview.router)
    application.include_router(agents.router)
    application.include_router(actions.router)
    application.include_router(audit.router)

    @application.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": "quietward-response",
            "health": "/health",
            "docs": "/docs",
        }

    return application


def runtime_app() -> FastAPI:
    """Uvicorn application factory for the migrated runtime schema."""
    return create_app(create_schema=False)
