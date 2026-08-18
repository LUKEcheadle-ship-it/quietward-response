from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import events, health, hosts, incidents, overview
from app.config import Settings, get_settings
from app.database.session import Database
from app.logging import configure_logging
from app.services.audit_service import record_audit


def create_app(
    *,
    database_url: str | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    resolved = settings or get_settings()
    if database_url:
        resolved = resolved.model_copy(update={"database_url": database_url})
    configure_logging(resolved.log_level)
    database = Database(resolved.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.create_all()
        yield
        database.dispose()

    application = FastAPI(
        title="QuietWard Response API",
        version="0.1.0",
        description="Deterministic event ingestion, incident correlation, investigation, and audit.",
        lifespan=lifespan,
    )
    application.state.database = database
    application.state.settings = resolved
    application.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-Actor-ID"],
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

    @application.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": "quietward-response",
            "health": "/health",
            "docs": "/docs",
        }

    return application


app = create_app()
