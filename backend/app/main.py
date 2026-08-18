import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import events, health, hosts, incidents
from app.config import settings
from app.database.models import Base
from app.database.session import SessionLocal, engine
from app.models import Audit, Event, Host, Incident  # noqa: F401
from app.services.audit_service import record_audit

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", description="Explainable incident investigation and response coordination", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type"])


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path.endswith("/events") and request.method == "POST":
        body = exc.body if isinstance(exc.body, dict) else {}
        resource_id = str(body.get("event_id", "unknown"))
        with SessionLocal() as db:
            record_audit(db, action="event.rejected", resource_type="event", resource_id=resource_id,
                         details={"reason": "schema validation", "errors": [{"location": list(item["loc"]), "type": item["type"]} for item in exc.errors()]})
            db.commit()
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": exc.errors()}))


app.include_router(health.router, prefix="/api/v1")
app.include_router(events.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
app.include_router(hosts.router, prefix="/api/v1")


@app.get("/")
def root() -> dict:
    return {"service": settings.app_name, "docs": "/docs", "health": "/api/v1/health"}
