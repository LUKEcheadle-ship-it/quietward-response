from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


_ROLE_RANK = {"viewer": 1, "responder": 2, "admin": 3}
_PENDING_ACTION_RE = re.compile(r"^/api/v1/agents/[^/]+/actions/pending$")
_CAPABILITIES_RE = re.compile(r"^/api/v1/agents/[^/]+/capabilities$")
_ROTATE_KEY_RE = re.compile(r"^/api/v1/agents/[^/]+/rotate-key$")
_ACTIVATE_KEY_RE = re.compile(r"^/api/v1/agents/[^/]+/activate-key$")
_RESULT_RE = re.compile(r"^/api/v1/actions/[^/]+/result$")
_AGENT_PATCH_RE = re.compile(r"^/api/v1/agents/[^/]+$")
_ACTION_DECISION_RE = re.compile(r"^/api/v1/actions/[^/]+/(?:approve|reject)$")
_INCIDENT_ACTION_RE = re.compile(r"^/api/v1/incidents/[^/]+/actions$")
_INCIDENT_RE = re.compile(r"^/api/v1/incidents/[^/]+$")
_AUDIT_CHECKPOINT_VERIFY = "/api/v1/audit/checkpoint/verify"


@dataclass(frozen=True, slots=True)
class AnalystIdentity:
    actor_id: str
    role: str


def _credentials(settings) -> tuple[tuple[str, str, str], ...]:
    values: list[tuple[str, str, str]] = []
    for entry in settings.analyst_credentials:
        actor_id, role, token_hash = (item.strip() for item in entry.split("|", 2))
        values.append((actor_id[:128], role.lower(), token_hash.lower()))
    return tuple(values)


def _machine_authenticated_endpoint(method: str, path: str) -> bool:
    if method == "OPTIONS":
        return True
    if method == "POST" and path == "/api/v1/events":
        return True
    if method == "POST" and path == "/api/v1/agents/enroll":
        return True
    if method == "POST" and _CAPABILITIES_RE.fullmatch(path):
        return True
    if method == "POST" and _ROTATE_KEY_RE.fullmatch(path):
        return True
    if method == "POST" and _ACTIVATE_KEY_RE.fullmatch(path):
        return True
    if method == "GET" and _PENDING_ACTION_RE.fullmatch(path):
        return True
    if method == "POST" and _RESULT_RE.fullmatch(path):
        return True
    return False


def _required_role(method: str, path: str) -> str:
    if method == "POST" and path == _AUDIT_CHECKPOINT_VERIFY:
        return "viewer"
    if method == "PATCH" and _AGENT_PATCH_RE.fullmatch(path):
        return "admin"
    if method == "PATCH" and _INCIDENT_RE.fullmatch(path):
        return "responder"
    if method == "POST" and _ACTION_DECISION_RE.fullmatch(path):
        return "responder"
    if method == "POST" and _INCIDENT_ACTION_RE.fullmatch(path):
        return "responder"
    if method in {"POST", "PATCH", "PUT", "DELETE"}:
        return "admin"
    return "viewer"


def _bearer_token(request: Request) -> str | None:
    value = request.headers.get("authorization", "").strip()
    if not value:
        return None
    scheme, separator, token = value.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _authenticate_bearer(request: Request) -> AnalystIdentity | None:
    token = _bearer_token(request)
    if token is None or len(token) > 512:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    for actor_id, role, expected_hash in _credentials(request.app.state.settings):
        if hmac.compare_digest(digest, expected_hash):
            return AnalystIdentity(actor_id=actor_id, role=role)
    return None


def analyst_actor_id(request: Request, fallback_header: str | None = None) -> str:
    identity = getattr(request.state, "analyst_identity", None)
    if isinstance(identity, AnalystIdentity):
        return identity.actor_id
    fallback = str(fallback_header or "").strip() or "local-analyst"
    return fallback[:128]


class AnalystAuthMiddleware(BaseHTTPMiddleware):
    """RBAC for human analyst API traffic while preserving machine auth protocols."""

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method.upper()
        path = request.url.path
        if not path.startswith("/api/v1") or _machine_authenticated_endpoint(method, path):
            return await call_next(request)

        required = _required_role(method, path)
        identity = _authenticate_bearer(request)

        if identity is None and request.app.state.settings.development_actor_header_allowed:
            actor_header = request.headers.get("X-Actor-ID", "").strip() or "local-analyst"
            identity = AnalystIdentity(actor_id=actor_header[:128], role="admin")

        if identity is None:
            return JSONResponse(
                status_code=401,
                content={
                    "detail": {
                        "code": "analyst_authentication_required",
                        "message": "valid analyst bearer authentication is required",
                    }
                },
                headers={"WWW-Authenticate": "Bearer"},
            )

        if _ROLE_RANK.get(identity.role, 0) < _ROLE_RANK[required]:
            return JSONResponse(
                status_code=403,
                content={
                    "detail": {
                        "code": "analyst_role_insufficient",
                        "required_role": required,
                    }
                },
            )

        request.state.analyst_identity = identity
        response = await call_next(request)
        response.headers["X-QWR-Analyst-Role"] = identity.role
        return response
