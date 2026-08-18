from __future__ import annotations

import asyncio

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class SerializedRequestMiddleware(BaseHTTPMiddleware):
    """Serialize v1 API requests within one server process.

    Several v1 operations append to a single hash-chained audit log as part of the
    same database transaction as the business change. Serializing requests keeps
    two concurrent transactions from independently choosing the same audit head.

    v1 intentionally runs a single Uvicorn process/worker. A future horizontally
    scaled deployment must replace this process-local guard with a database-backed
    atomic chain-head/append mechanism before adding multiple API workers.
    """

    def __init__(self, app) -> None:  # type intentionally follows Starlette middleware API
        super().__init__(app)
        self._lock = asyncio.Lock()

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        async with self._lock:
            return await call_next(request)
