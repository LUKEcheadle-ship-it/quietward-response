"""Named bearer-token analysts, independent of endpoint HMAC credentials."""
from __future__ import annotations
import hashlib
import hmac
import re
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def authenticated_analyst(request: Request) -> str:
    hashes = request.app.state.settings.analyst_token_hashes
    if not hashes:
        return request.headers.get("X-Actor-ID", "local-analyst").strip()[:128] or "local-analyst"
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not 32 <= len(token) <= 512:
        raise HTTPException(status_code=401, detail="Analyst authentication required")
    digest = hashlib.sha256(token.encode()).hexdigest()
    identity = None
    for name, expected in hashes.items():
        if hmac.compare_digest(digest, expected):
            identity = name
    if identity is None:
        raise HTTPException(status_code=401, detail="Invalid analyst credential")
    return identity


def agent_route(method: str, path: str) -> bool:
    # These routes retain their own HMAC/enrollment validation. Never authorize
    # agent requests merely because they carry an analyst token.
    return ((method == "POST" and path in {"/api/v1/events", "/api/v1/agents/enroll"})
            or (method == "POST" and re.fullmatch(r"/api/v1/agents/[^/]+/capabilities", path) is not None)
            or (method == "GET" and re.fullmatch(r"/api/v1/agents/[^/]+/actions/pending", path) is not None)
            or (method == "POST" and re.fullmatch(r"/api/v1/actions/[^/]+/result", path) is not None))


class AnalystAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path.rstrip("/")
        if (request.method == "OPTIONS" or not path.startswith("/api/v1")
                or path == "/api/v1/access" or agent_route(request.method, path)):
            return await call_next(request)
        try:
            actor = authenticated_analyst(request)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                                headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"})
        if request.app.state.settings.analyst_token_hashes:
            # Bind existing approval/audit handlers to server-verified identity.
            headers = [(k, v) for k, v in request.scope["headers"] if k.lower() != b"x-actor-id"]
            request.scope["headers"] = headers + [(b"x-actor-id", actor.encode("ascii"))]
            if hasattr(request, "_headers"):
                del request._headers
        return await call_next(request)
