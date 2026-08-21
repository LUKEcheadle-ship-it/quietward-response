from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"
_MAX_REDACTION_DEPTH = 20

# Exact and suffix forms intentionally focus on credential material rather than
# broad words such as `key`, which would destroy useful identifiers like key_id.
_EXACT_SENSITIVE_KEYS = {
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "password",
    "passwd",
    "passphrase",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "bearer_token",
    "private_key",
    "credential",
    "credentials",
}
_SENSITIVE_SUFFIXES = (
    "_password",
    "_passwd",
    "_passphrase",
    "_secret",
    "_token",
    "_api_key",
    "_private_key",
    "_authorization",
    "_cookie",
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|client_secret|api_key|apikey|"
    r"access_token|refresh_token|id_token|session_token|bearer_token)\s*[:=]\s*"
    r"([^\s,;]+|\"[^\"]*\"|'[^']*')"
)


def _normalized_key(key: object) -> str:
    return str(key).strip().casefold().replace("-", "_").replace(" ", "_")


def is_sensitive_key(key: object) -> bool:
    normalized = _normalized_key(key)
    if normalized in _EXACT_SENSITIVE_KEYS:
        return True
    return any(normalized.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES)


def redact_sensitive_text(value: str) -> str:
    text = _BEARER_RE.sub("Bearer " + REDACTED, value)

    def replacement(match: re.Match[str]) -> str:
        return f"{match.group(1)}={REDACTED}"

    return _ASSIGNMENT_RE.sub(replacement, text)


def redact_sensitive(value: Any, *, _depth: int = 0) -> Any:
    """Return a JSON-compatible copy with obvious credential material removed.

    The function intentionally does not mutate the input. A depth ceiling prevents
    adversarial recursive/nested payloads from turning redaction into an unbounded
    traversal even before normal schema/size limits are applied.
    """
    if _depth >= _MAX_REDACTION_DEPTH:
        return "[REDACTED:DEPTH_LIMIT]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_sensitive_key(key_text):
                result[key_text] = REDACTED
            else:
                result[key_text] = redact_sensitive(item, _depth=_depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_sensitive(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value
