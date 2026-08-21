from __future__ import annotations

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
from app.services.audit_service import (
    backfill_legacy_audit_chain,
    record_audit,
    verify_audit_chain,
)


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
            yield
        finally:
            database.dispose()

    application = FastAPI(
        title="QuietWard Response API",
        version=__version__,
        description=(
            "Deterministic event ingestion, incident correlation, investigation, "
            "authenticated agents, policy-controlled response actions, and tamper-evident audit."
        ),
        lifespan=lifespan,
    )
    application.state.database = database
    application.state.settings = resolved
    application.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=[
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
    # Current qualification is one API process/worker. The same middleware keeps
    # the linear audit chain serialized and enforces process-local request/rate
    # bounds until a future shared multi-worker control plane is qualified.
    application.add_middleware(
        SerializedRequestMiddleware,
        max_request_bytes=resolved.api_max_request_bytes,
        rate_limit_per_minute=resolved.api_rate_limit_per_minute,
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
