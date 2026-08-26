from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_frontend_refuses_remote_plaintext_bearer_api_transport() -> None:
    text = (ROOT / "frontend" / "src" / "lib" / "api.ts").read_text(encoding="utf-8")
    assert "validatedApiUrl" in text
    assert 'parsed.protocol === "http:" && !loopback' in text
    assert "Remote QuietWard Response analyst API URLs must use HTTPS" in text
    assert "NEXT_PUBLIC_API_URL must not contain credentials, a path, query, or fragment" in text
    assert "sessionStorage" in text
