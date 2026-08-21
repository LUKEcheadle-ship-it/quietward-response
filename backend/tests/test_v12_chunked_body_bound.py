from __future__ import annotations

from collections import deque

import pytest
from starlette.requests import Request

from app.request_serialization import SerializedRequestMiddleware


class _NoopApp:
    async def __call__(self, scope, receive, send):  # pragma: no cover - not used directly
        raise AssertionError("noop app should not be called")


def _request(chunks: list[bytes]) -> Request:
    messages = deque(
        {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks) - 1,
        }
        for index, chunk in enumerate(chunks)
    )
    if not messages:
        messages.append({"type": "http.request", "body": b"", "more_body": False})

    async def receive():
        if messages:
            return messages.popleft()
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/events",
            "raw_path": b"/api/v1/events",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8002),
        },
        receive,
    )


@pytest.mark.asyncio
async def test_chunked_body_is_buffered_only_when_within_limit_and_remains_replayable() -> None:
    middleware = SerializedRequestMiddleware(_NoopApp(), max_request_bytes=10, rate_limit_per_minute=30)
    request = _request([b"abc", b"def", b"ghij"])
    assert await middleware._buffer_bounded_body(request) is True
    assert await request.body() == b"abcdefghij"


@pytest.mark.asyncio
async def test_chunked_body_rejects_immediately_after_crossing_limit() -> None:
    middleware = SerializedRequestMiddleware(_NoopApp(), max_request_bytes=10, rate_limit_per_minute=30)
    request = _request([b"12345", b"67890", b"X", b"should-not-be-needed"])
    assert await middleware._buffer_bounded_body(request) is False
    # The middleware must not create a retained body buffer larger than the limit.
    assert not hasattr(request, "_body")


def test_request_middleware_source_does_not_trust_forwarded_for() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    source = (root / "backend" / "app" / "request_serialization.py").read_text(encoding="utf-8")
    assert "request.client.host" in source
    assert 'request.headers.get("x-forwarded-for")' not in source.lower()
    assert "_buffer_bounded_body" in source
    assert "total > self._max_request_bytes" in source
