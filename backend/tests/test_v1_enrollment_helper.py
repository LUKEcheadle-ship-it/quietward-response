from __future__ import annotations

from pathlib import Path

import pytest

from scripts import enroll_quietward


def test_enrollment_helper_follows_nondefault_api_port(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "QWR_API_PORT=9123\nNEXT_PUBLIC_API_URL=http://localhost:8002\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(enroll_quietward, "ENV_FILE", env_file)
    monkeypatch.delenv("QWR_API_PORT", raising=False)
    monkeypatch.delenv("NEXT_PUBLIC_API_URL", raising=False)

    assert enroll_quietward._resolve_api_url(None) == "http://127.0.0.1:9123"


def test_enrollment_helper_accepts_explicit_https_root_url() -> None:
    assert (
        enroll_quietward._resolve_api_url("https://response.example.test:8443/")
        == "https://response.example.test:8443"
    )


def test_enrollment_helper_rejects_embedded_credentials_or_api_path() -> None:
    with pytest.raises(ValueError, match="credentials"):
        enroll_quietward._resolve_api_url("https://user:pass@example.test")
    with pytest.raises(ValueError, match="must not include an API path"):
        enroll_quietward._resolve_api_url("https://example.test/api/v1")
