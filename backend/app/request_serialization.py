from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class SerializedRequestMiddleware(BaseHTTPMiddleware):
    """Serialize API writes and apply shared response hardening/abuse bounds.

    The current qualified runtime is intentionally one API process/worker. The
    process-local rate limiter therefore matches the existing audit-chain runtime
    boundary; a future multi-worker deployment must use shared atomic state.
    """

    def __init__(
        self,
        app,
        *,
        max_request_bytes: int = 1_048_576,
        rate_limit_per_minute: int = 600,
    ) -> None:  # type intentionally follows Starlette middleware API
        super().__init__(app)
        self._lock = asyncio.Lock()
        self._max_request_bytes = max_request_bytes
        self._rate_limit_per_minute = rate_limit_per_minute
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def _harden(self, request: Request, response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/v1"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
        return response

    def _rate_key(self, request: Request) -> str:
        client = request.client.host if request.client is not None else "unknown"
        return client[:128]

    def _rate_allowed(self, request: Request, now: float) -> bool:
        if not request.url.path.startswith("/api/v1"):
            return True
        key = self._rate_key(request)
        bucket = self._requests[key]
        cutoff = now - 60.0
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= self._rate_limit_per_minute:
            return False
        bucket.append(now)

        # Keep attacker-controlled source cardinality bounded in the single-worker
        # process. Oldest empty/stale buckets are discarded opportunistically.
        if len(self._requests) > 2048:
            for candidate in list(self._requests)[:512]:
                values = self._requests[candidate]
                while values and values[0] <= cutoff:
                    values.popleft()
                if not values:
                    self._requests.pop(candidate, None)
        return True

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self._rate_allowed(request, time.monotonic()):
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": {
                        "code": "api_rate_limit_exceeded",
                        "message": "API request rate limit exceeded",
                    }
                },
                headers={"Retry-After": "60"},
            )
            return self._harden(request, response)

        content_length = request.headers.get("content-length")
        if content_length:
            try:
                advertised = int(content_length)
            except ValueError:
                advertised = -1
            if advertised < 0 or advertised > self._max_request_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": {
                            "code": "request_too_large",
                            "message": "request body exceeds configured limit",
                        }
                    },
                )
                return self._harden(request, response)

        if request.method.upper() in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > self._max_request_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": {
                            "code": "request_too_large",
                            "message": "request body exceeds configured limit",
                        }
                    },
                )
                return self._harden(request, response)

        async with self._lock:
            response = await call_next(request)
        return self._harden(request, response)
